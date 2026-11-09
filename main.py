"""CLI entrypoint: analyze a list of URLs and write results.json.

    python -m hunter.main --urls urls.txt --out output --concurrency 4
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path

from playwright.async_api import async_playwright

from .agent import explore
from .browser import (NetworkLog, load, new_context, screenshot, screenshot_address,
                      snapshot)
from .classify import classify
from .extract import AddressStore
from .llm import LLM

log = logging.getLogger("hunter")

EXPLORE_IF_CONFIDENCE_BELOW = 0.75


def slug(url: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", url.split("://", 1)[-1]).strip("_")[:80]


async def analyze(url: str, browser, pw, llm: LLM, args, shots_dir: Path) -> dict:
    rec = {
        "url": url, "final_url": None, "status": "pending", "http_status": None,
        "classification": None, "confidence": None, "category": None, "reasoning": None,
        "red_flags": [], "crypto_addresses": [], "low_confidence_candidates": [],
        "screenshots": [], "exploration": None, "error": None, "elapsed_s": None,
    }
    t0 = time.time()
    try:
        await asyncio.wait_for(_analyze(url, rec, browser, pw, llm, args, shots_dir),
                               timeout=args.site_timeout)
    except asyncio.TimeoutError:
        rec["error"] = (rec["error"] or "") + " site timeout"
    except Exception as e:  # never let one site kill the run
        log.exception("unhandled error on %s", url)
        rec["error"] = f"{e.__class__.__name__}: {e}"[:300]
    if rec["classification"] is None:  # timed out / crashed before classification
        v = await classify(llm, url, None, [], reachable=False)
        rec.update(classification=v["label"], confidence=min(v["confidence"], 0.5),
                   category=v.get("category"), reasoning=v.get("reasoning"),
                   red_flags=v.get("red_flags", []))
        rec["status"] = rec["status"] if rec["status"] != "pending" else "error"
    rec["elapsed_s"] = round(time.time() - t0, 1)
    return rec


async def _analyze(url, rec, browser, pw, llm, args, shots_dir: Path):
    ctx = await new_context(browser, pw, url)
    store = AddressStore()
    base = slug(url)
    try:
        page = await ctx.new_page()
        page.on("dialog", lambda d: asyncio.ensure_future(d.accept()))
        net = NetworkLog(page)

        async def harvest(p):
            snap = await snapshot(p)
            new = []
            new += store.add(snap["text"], "visible_text", p.url)
            new += store.add(snap["dom_values"], "dom_value", p.url)
            new += store.add(snap["html"], "html", p.url)
            for body_url, body, is_js in await net.take():
                new += store.add(body, "network_js" if is_js else "network_api", body_url)
            # Bonus: screenshot each newly-found address in context, while it's on screen.
            for f in new:
                path = shots_dir / f"{base}__{f.address[:12]}.png"
                if await screenshot_address(p, f.address, str(path)):
                    rec["screenshots"].append(str(path))
            # Cap stored network evidence size via the store; return snapshot for callers.
            return snap

        status, err = await load(page, url, timeout_ms=args.nav_timeout * 1000)
        rec["http_status"], rec["error"] = status, err
        snap = await harvest(page)
        rec["final_url"] = page.url
        reachable = len(snap["text"].strip()) > 20 or len(snap["html"]) > 1500
        if err and err.startswith("net::") or not reachable:
            rec["status"] = "unreachable"
            reachable = False
        else:
            rec["status"] = "ok"
            landing = await screenshot(page, str(shots_dir / f"{base}__landing.png"))
            if landing:
                rec["screenshots"].insert(0, landing)

        addrs = [f.to_dict() for f in store.confirmed()]
        verdict = await classify(llm, url, snap, addrs, reachable=reachable)

        # Explore if it looks like a scam (to find hidden addresses) or we're unsure (to gather evidence).
        should_explore = (reachable and llm.enabled and args.max_steps > 0 and
                          (verdict["label"] == "SCAM" or verdict["confidence"] < EXPLORE_IF_CONFIDENCE_BELOW))
        if should_explore:
            exp = await explore(page, llm, page.url, harvest,
                                lambda: [f"{f.address} ({f.asset_hint})" for f in store.confirmed()],
                                max_steps=args.max_steps)
            rec["exploration"] = {"steps": exp["steps"], "persona_email": exp["persona_email"]}
            addrs = [f.to_dict() for f in store.confirmed()]
            # Re-classify with what the agent saw behind the login wall.
            verdict = await classify(llm, url, snap, addrs,
                                     extra_evidence="\n".join(exp["steps"]) + "\n" + exp["visited_text"],
                                     reachable=True)

        rec.update(classification=verdict["label"], confidence=round(verdict["confidence"], 2),
                   category=verdict.get("category"), reasoning=verdict.get("reasoning"),
                   red_flags=verdict.get("red_flags", []))
        rec["crypto_addresses"] = [f.to_dict() for f in store.confirmed()]
        rec["low_confidence_candidates"] = [f.to_dict() for f in store.low_confidence()][:20]
    finally:
        await ctx.close()


def write_address_index(results: list[dict], path: Path) -> None:
    """Invert results to address -> sites. An address reused across sites links them to one operator."""
    index: dict[str, dict] = {}
    for r in results:
        for a in r["crypto_addresses"]:
            key = a["address"].lower() if a["network"] == "EVM" else a["address"]
            e = index.setdefault(key, {"address": a["address"], "network": a["network"],
                                       "asset_hints": set(), "sites": []})
            e["asset_hints"].add(a["asset_hint"])
            e["sites"].append(r["url"])
    rows = sorted(index.values(), key=lambda e: (-len(e["sites"]), e["address"]))
    for e in rows:
        e["asset_hints"] = sorted(e["asset_hints"])
        e["site_count"] = len(e["sites"])
    path.write_text(json.dumps(rows, indent=2))
    shared = [e for e in rows if e["site_count"] > 1]
    if shared:
        log.info("%d addresses are shared across multiple sites (see %s)", len(shared), path.name)


def load_done(jsonl: Path) -> dict[str, dict]:
    done = {}
    if jsonl.exists():
        for line in jsonl.read_text().splitlines():
            try:
                r = json.loads(line)
                done[r["url"]] = r
            except Exception:
                pass
    return done


async def run(args):
    out = Path(args.out)
    shots = out / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    jsonl = out / "results.jsonl"
    if args.fresh and jsonl.exists():
        jsonl.unlink()

    urls = [u.strip() for u in Path(args.urls).read_text().splitlines()
            if u.strip() and not u.startswith("#")]
    urls = list(dict.fromkeys(urls))
    if args.limit:
        urls = urls[: args.limit]
    done = load_done(jsonl)
    todo = [u for u in urls if u not in done]

    llm = LLM()
    log.info("%d URLs (%d already done). LLM %s (%s)", len(urls), len(done),
             "enabled" if llm.enabled else "DISABLED - heuristic only", llm.model)

    sem = asyncio.Semaphore(args.concurrency)
    lock = asyncio.Lock()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])

        async def worker(u):
            async with sem:
                r = await analyze(u, browser, pw, llm, args, shots)
                async with lock:
                    with jsonl.open("a") as fh:
                        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                done[u] = r
                log.info("[%d/%d] %-45s %-9s %-8s conf=%s addrs=%d", len(done), len(urls), u[:45],
                         r["status"], r["classification"], r["confidence"], len(r["crypto_addresses"]))

        await asyncio.gather(*(worker(u) for u in todo))
        await browser.close()

    results = [done[u] for u in urls if u in done]
    (out / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    write_address_index(results, out / "address_index.json")
    scams = sum(r["classification"] == "SCAM" for r in results)
    with_addr = sum(bool(r["crypto_addresses"]) for r in results)
    n_addr = sum(len(r["crypto_addresses"]) for r in results)
    log.info("Done: %d sites, %d SCAM, %d with addresses (%d addresses). LLM calls: %d",
             len(results), scams, with_addr, n_addr, llm.calls)


def main():
    p = argparse.ArgumentParser(description="Classify scam sites and extract crypto addresses.")
    p.add_argument("--urls", default="urls.txt")
    p.add_argument("--out", default="output")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--max-steps", type=int, default=10, help="agent exploration steps per site (0 = off)")
    p.add_argument("--nav-timeout", type=int, default=30, help="seconds for initial page load")
    p.add_argument("--site-timeout", type=int, default=300, help="hard cap in seconds per site")
    p.add_argument("--limit", type=int, default=0, help="only process the first N URLs (testing)")
    p.add_argument("--fresh", action="store_true", help="ignore previous results.jsonl")
    args = p.parse_args()
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

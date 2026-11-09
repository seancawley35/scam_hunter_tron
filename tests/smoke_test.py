"""End-to-end smoke test against a local fake scam site, no API key needed.

A scripted FakeLLM stands in for Claude so the real browser, agent loop,
network capture, extraction and screenshot code all run.

    python tests/smoke_test.py
"""
import asyncio
import functools
import http.server
import json
import os
import re
import sys
import tempfile
import threading
from types import SimpleNamespace

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from hunter import main as hm  # noqa: E402


class FakeLLM:
    enabled = True
    model = "fake"
    calls = 0

    async def json(self, system, user, max_tokens=800):
        self.calls += 1
        if "fraud analyst" in system:  # classifier
            return {"label": "SCAM", "confidence": 0.9, "category": "fake exchange",
                    "reasoning": "guaranteed daily profit", "red_flags": ["daily profit"]}
        els = json.loads(re.search(r"href\):\n(\[.*?\])\n", user, re.S).group(1))
        by_text = {e["text"]: e["id"] for e in els}
        found = re.search(r"Addresses already found: (.*)", user).group(1)
        if "Register" in by_text:
            return {"thought": "go register", "actions": [{"action": "click", "id": by_text["Register"]}]}
        if "Create account" in by_text:
            fields = [e for e in els if e["tag"] == "input"]
            return {"thought": "fill form", "actions": [
                {"action": "fill", "id": fields[0]["id"], "value": "a@mailinator.com"},
                {"action": "fill", "id": fields[1]["id"], "value": "Pw#12345"},
                {"action": "click", "id": by_text["Create account"]}]}
        if "ERC20" in by_text and "ERC-20" not in found:
            return {"thought": "switch network", "actions": [{"action": "click", "id": by_text["ERC20"]}]}
        return {"thought": "found both", "actions": [{"action": "done", "reason": "addresses found"}]}


def serve(directory):
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass

    handler = functools.partial(Quiet, directory=directory)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


async def main():
    srv = serve(os.path.join(os.path.dirname(__file__), "fake_site"))
    url = f"http://127.0.0.1:{srv.server_address[1]}/index.html"
    out = tempfile.mkdtemp()
    urls = os.path.join(out, "urls.txt")
    open(urls, "w").write(url + "\nhttps://this-domain-does-not-exist-hunter.invalid\n")
    args = SimpleNamespace(urls=urls, out=out, concurrency=2, max_steps=6, nav_timeout=15,
                           site_timeout=120, limit=0, fresh=True)
    hm.LLM = FakeLLM
    await hm.run(args)
    results = json.load(open(os.path.join(out, "results.json")))
    ok, dead = results
    print(json.dumps(ok, indent=2)[:3000])
    addrs = {a["asset_hint"] for a in ok["crypto_addresses"]}
    assert ok["classification"] == "SCAM", ok
    assert any("TRC-20" in a for a in addrs) and any("ERC-20" in a or "EVM" in a for a in addrs), addrs
    assert dead["status"] == "unreachable", dead
    assert any("__landing" in s for s in ok["screenshots"])
    print("\nSMOKE TEST PASSED. Output in", out)


if __name__ == "__main__":
    asyncio.run(main())

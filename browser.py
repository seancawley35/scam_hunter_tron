"""Playwright helpers: isolated contexts, page loading, snapshots, network capture, screenshots."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from playwright.async_api import Error as PWError
from playwright.async_api import TimeoutError as PWTimeout

DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

# Many fake-exchange templates are mobile-only "h5"/"wap" apps that render blank on desktop.
MOBILE_HOST_PREFIXES = ("h5.", "m.", "wap.")
MOBILE_PATH_HINTS = ("/h5", "/wap")

# Keep navigation in one tab: rewrite window.open and target=_blank so the agent
# never loses the page it is driving.
INIT_SCRIPT = r"""
window.open = function(u){ if (u) { location.href = u; } return window; };
document.addEventListener('click', function(e){
  const a = e.target && e.target.closest ? e.target.closest('a[target]') : null;
  if (a) a.removeAttribute('target');
}, true);
"""

COLLECT_JS = r"""
() => {
  const out = [];
  document.querySelectorAll('input, textarea').forEach(e => { if (e.value) out.push(e.value); });
  try { out.push(JSON.stringify(localStorage)); } catch (e) {}
  try { out.push(JSON.stringify(sessionStorage)); } catch (e) {}
  return out;
}
"""

HIGHLIGHT_JS = r"""
(addr) => {
  let el = null;
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (w.nextNode()) {
    if (w.currentNode.nodeValue && w.currentNode.nodeValue.includes(addr)) { el = w.currentNode.parentElement; break; }
  }
  if (!el) {
    for (const i of document.querySelectorAll('input, textarea')) {
      if (i.value && i.value.includes(addr)) { el = i; break; }
    }
  }
  if (!el) return false;
  el.scrollIntoView({block: 'center'});
  el.style.outline = '4px solid #ff0033';
  el.style.outlineOffset = '3px';
  return true;
}
"""

CDN_HOSTS = ("cdnjs.", "jsdelivr", "unpkg", "googleapis", "gstatic", "cloudflare",
             "googletagmanager", "google-analytics", "facebook", "hotjar", "jquery")


def wants_mobile(url: str) -> bool:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    return host.startswith(MOBILE_HOST_PREFIXES) or any(h in p.path.lower() for h in MOBILE_PATH_HINTS)


def site_key(url: str) -> str:
    """Rough registrable domain (last two labels). Good enough to keep the agent on-site."""
    host = (urlparse(url).hostname or "").lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def same_site(a: str, b: str) -> bool:
    return site_key(a) == site_key(b)


async def new_context(browser, playwright, url: str):
    common = dict(accept_downloads=False, ignore_https_errors=True, java_script_enabled=True,
                  permissions=[], service_workers="block")
    if wants_mobile(url):
        ctx = await browser.new_context(**playwright.devices["iPhone 13"], **common)
    else:
        ctx = await browser.new_context(user_agent=DESKTOP_UA,
                                        viewport={"width": 1366, "height": 900}, **common)
    ctx.set_default_timeout(15000)
    await ctx.add_init_script(INIT_SCRIPT)
    # Never follow non-http schemes (tg://, whatsapp://, wallet deep links, file://)
    await ctx.route(re.compile(r"^(?!https?:|data:|blob:).*"), lambda r: r.abort())
    return ctx


class NetworkLog:
    """Captures text bodies of XHR/fetch/document/script responses.

    Fake exchanges usually fetch the deposit address from a JSON API after login,
    so the address is often in network traffic before (or instead of) the DOM.
    """

    TEXT_TYPES = ("json", "javascript", "text/", "xml")

    def __init__(self, page):
        self._bodies: list[tuple[str, str, bool]] = []
        self._tasks: set[asyncio.Task] = set()
        page.on("response", self._on_response)

    def _on_response(self, resp):
        t = asyncio.ensure_future(self._grab(resp))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _grab(self, resp):
        try:
            if resp.request.resource_type in ("image", "font", "media", "stylesheet"):
                return
            ct = (resp.headers.get("content-type") or "").lower()
            if not any(t in ct for t in self.TEXT_TYPES):
                return
            host = (urlparse(resp.url).hostname or "").lower()
            is_js = "javascript" in ct
            if is_js and any(c in host for c in CDN_HOSTS):
                return
            body = await resp.body()
            if len(body) > 3_000_000:
                return
            self._bodies.append((resp.url, body.decode("utf-8", errors="ignore"), is_js))
        except Exception:
            pass

    async def take(self, timeout: float = 5.0) -> list[tuple[str, str, bool]]:
        """Wait for in-flight body reads, then return and clear captured bodies."""
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=timeout)
        out, self._bodies = self._bodies, []
        return out


def short_error(e: Exception) -> str:
    m = re.search(r"net::ERR_[A-Z_]+", str(e))
    return m.group() if m else str(e).splitlines()[0][:200]


async def settle(page, idle_ms: int = 8000, extra_ms: int = 2500):
    try:
        await page.wait_for_load_state("networkidle", timeout=idle_ms)
    except Exception:
        pass
    await page.wait_for_timeout(extra_ms)


async def load(page, url: str, timeout_ms: int = 30000) -> tuple[int | None, str | None]:
    """Navigate to url. Returns (http_status, error). A timeout is soft: the page may still have content."""
    status, err = None, None
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        status = resp.status if resp else None
    except PWTimeout:
        err = "timeout"
    except PWError as e:
        return None, short_error(e)
    await settle(page)
    return status, err


async def snapshot(page) -> dict:
    snap = {"url": page.url, "title": "", "text": "", "html": "", "dom_values": ""}
    try:
        snap["title"] = await page.title()
    except Exception:
        pass
    try:
        snap["text"] = await page.inner_text("body", timeout=5000)
    except Exception:
        pass
    htmls = []
    for f in page.frames:
        try:
            htmls.append(await f.content())
        except Exception:
            pass
    snap["html"] = "\n".join(htmls)
    try:
        snap["dom_values"] = "\n".join(await page.evaluate(COLLECT_JS))
    except Exception:
        pass
    return snap


async def screenshot(page, path: str, full_page: bool = False) -> str | None:
    try:
        await page.screenshot(path=path, full_page=full_page, timeout=10000)
        return path
    except Exception:
        return None


async def screenshot_address(page, address: str, path: str) -> str | None:
    """Scroll to the address, outline it in red, and capture the viewport."""
    try:
        if not await page.evaluate(HIGHLIGHT_JS, address):
            return None
    except Exception:
        return None
    await page.wait_for_timeout(300)
    return await screenshot(page, path)

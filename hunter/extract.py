"""Crypto address extraction with checksum validation.

Regex alone produces lots of false positives (hashes, IDs, minified JS), so every
candidate is validated:
  - BTC legacy / P2SH  -> Base58Check, version byte 0x00 / 0x05
  - BTC SegWit/Taproot -> Bech32 / Bech32m checksum (hrp "bc")
  - TRON (TRC-20)      -> Base58Check, version byte 0x41
  - EVM (ETH, ERC-20, BEP-20) -> 0x + 40 hex (no keccak dependency in v1)
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

RE_BTC_LEGACY = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
RE_BTC_BECH32 = re.compile(r"\bbc1[02-9ac-hj-np-z]{11,71}\b", re.IGNORECASE)
RE_EVM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")

# Addresses that show up on many pages but are never a scammer's receiving wallet:
# token contracts, burn/zero addresses, and well-known documentation examples.
EXCLUDE = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT ERC-20 contract
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC ERC-20 contract
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "0x55d398326f99059ff775485246999027b3197955",  # USDT BEP-20 contract
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",  # USDC BEP-20 contract
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "tr7nhqjekqxgtci8q8zy4pl8otszgjlj6t",          # USDT TRC-20 contract
    "tekxitehnzsmse2xqrbj4w32run966rdz8",          # USDC TRC-20 contract
    "1a1zp1ep5qgefi2dmptftl5slmv7divfna",          # BTC genesis (common example)
}


# ---------------------------------------------------------------- validation
def b58decode_check(s: str) -> bytes | None:
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        return None
    return payload


def b58encode_check(payload: bytes) -> str:
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def bech32_valid(addr: str) -> bool:
    if addr.lower() != addr and addr.upper() != addr:
        return False  # mixed case is invalid in bech32
    addr = addr.lower()
    pos = addr.rfind("1")
    hrp, data = addr[:pos], addr[pos + 1:]
    if hrp != "bc" or len(data) < 6:
        return False
    try:
        d = [BECH32_CHARSET.index(c) for c in data]
    except ValueError:
        return False
    hrp_exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    return _bech32_polymod(hrp_exp + d) in (1, 0x2BC830A3)  # bech32, bech32m


def valid_btc_legacy(a: str) -> bool:
    p = b58decode_check(a)
    return p is not None and len(p) == 21 and p[0] in (0x00, 0x05)


def valid_tron(a: str) -> bool:
    p = b58decode_check(a)
    return p is not None and len(p) == 21 and p[0] == 0x41


def valid_evm(a: str) -> bool:
    body = a[2:]
    # reject obvious non-addresses: all one character, or long runs of zeros
    return len(set(body.lower())) > 4 and "0" * 16 not in body


# ---------------------------------------------------------------- extraction
@dataclass
class Found:
    address: str
    network: str          # BTC | EVM | TRON
    asset_hint: str
    context: str
    source: str
    page_url: str
    sources: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "network": self.network,
            "asset_hint": self.asset_hint,
            "sources": sorted(self.sources),
            "first_seen_on": self.page_url,
            "context": self.context,
        }


def _asset_hint(network: str, ctx: str) -> str:
    c = ctx.lower()
    if network == "BTC":
        return "BTC"
    if network == "TRON":
        if "usdc" in c:
            return "USDC (TRC-20)"
        return "USDT (TRC-20)" if ("usdt" in c or "trc" in c) else "TRON (likely USDT TRC-20)"
    chain = "BEP-20" if ("bep20" in c or "bep-20" in c or "bsc" in c) else "ERC-20"
    if "usdc" in c:
        return f"USDC ({chain})"
    if "usdt" in c or "erc20" in c or "erc-20" in c:
        return f"USDT ({chain})"
    return "ETH / EVM"


def _context(text: str, start: int, end: int, width: int = 80) -> str:
    snippet = text[max(0, start - width): end + width]
    return re.sub(r"\s+", " ", snippet).strip()


def extract_addresses(text: str, source: str = "", page_url: str = "") -> list[Found]:
    """Return validated, de-duplicated addresses found in `text`."""
    if not text:
        return []
    found: dict[str, Found] = {}

    def add(addr: str, network: str, m: re.Match):
        key = addr.lower()
        if key in EXCLUDE or key in found:
            return
        ctx = _context(text, m.start(), m.end())
        found[key] = Found(addr, network, _asset_hint(network, ctx), ctx, source, page_url, {source})

    for m in RE_BTC_LEGACY.finditer(text):
        if valid_btc_legacy(m.group()):
            add(m.group(), "BTC", m)
    for m in RE_BTC_BECH32.finditer(text):
        if bech32_valid(m.group()):
            add(m.group(), "BTC", m)
    for m in RE_TRON.finditer(text):
        if valid_tron(m.group()):
            add(m.group(), "TRON", m)
    for m in RE_EVM.finditer(text):
        if valid_evm(m.group()):
            add(m.group(), "EVM", m)
    return list(found.values())


class AddressStore:
    """Accumulates addresses for one site across pages and sources.

    Addresses seen only inside JavaScript bundles are kept separately as
    low-confidence candidates (libraries embed router/contract addresses).
    """

    LOW_CONF_SOURCES = {"network_js"}

    def __init__(self):
        self.items: dict[str, Found] = {}

    def add(self, text: str, source: str, page_url: str) -> list[Found]:
        new = []
        for f in extract_addresses(text, source, page_url):
            key = f.address.lower()
            if key in self.items:
                self.items[key].sources.add(source)
            else:
                self.items[key] = f
                new.append(f)
        return new

    def confirmed(self) -> list[Found]:
        return [f for f in self.items.values() if f.sources - self.LOW_CONF_SOURCES]

    def low_confidence(self) -> list[Found]:
        return [f for f in self.items.values() if not (f.sources - self.LOW_CONF_SOURCES)]

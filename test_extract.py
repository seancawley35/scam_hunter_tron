import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hunter.extract import (AddressStore, b58encode_check, bech32_valid,
                            extract_addresses, valid_btc_legacy, valid_tron)

BTC_P2PKH = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BTC_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
BTC_BECH32 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
ETH = "0x52908400098527886E0F7030069857D2E4169EE7"
TRON = b58encode_check(bytes([0x41]) + bytes(range(1, 21)))


def test_validators():
    assert valid_btc_legacy(BTC_P2PKH)
    assert valid_btc_legacy(BTC_P2SH)
    assert not valid_btc_legacy(BTC_P2PKH[:-1] + "3")  # broken checksum
    assert bech32_valid(BTC_BECH32)
    assert not bech32_valid(BTC_BECH32[:-1] + "x")
    assert valid_tron(TRON)
    assert not valid_tron(TRON[:-1] + ("A" if TRON[-1] != "A" else "B"))


def test_extract_from_deposit_page():
    page = f"""
      <div>Deposit USDT (TRC20)</div><span class="addr">{TRON}</span>
      <p>ERC20 USDT address: {ETH}</p>
      BTC: {BTC_BECH32} or legacy {BTC_P2PKH}
      tx hash 0x{'ab' * 32} should be ignored
    """
    found = {f.address: f for f in extract_addresses(page, "html", "https://x")}
    assert set(found) == {TRON, ETH, BTC_BECH32, BTC_P2PKH}
    assert found[TRON].network == "TRON" and "TRC-20" in found[TRON].asset_hint
    assert found[ETH].network == "EVM" and "USDT" in found[ETH].asset_hint


def test_known_contracts_excluded():
    page = "USDT contract TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t and 0xdAC17F958D2ee523a2206206994597C13D831ec7"
    assert extract_addresses(page) == []


def test_store_confidence_split():
    s = AddressStore()
    s.add(f"var router='{ETH}'", "network_js", "https://x/app.js")
    assert [f.address for f in s.low_confidence()] == [ETH]
    s.add(f"Your deposit address {ETH}", "visible_text", "https://x/deposit")
    assert [f.address for f in s.confirmed()] == [ETH]
    assert s.low_confidence() == []

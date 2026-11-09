# Scam Hunter

An agentic pipeline that visits a list of URLs in a sandboxed headless browser, classifies each as
**SCAM / NOT_SCAM**, and extracts the cryptocurrency addresses scammers use to receive funds —
including addresses that only appear after registering, logging in, and opening a deposit page.

> v1 — built to get a complete, working end-to-end run first. See "What I'd do with more time".

## What an investigator gets

For every URL, one record answering the questions an analyst actually asks:

| question | where it's answered |
|---|---|
| Is this a scam, and how sure are we? | `classification`, `confidence`, `category`, plain-English `reasoning`, `red_flags` |
| Where do victims send money? | `crypto_addresses` — checksum-validated, with network, likely asset (e.g. USDT TRC-20) and surrounding text |
| Can I prove it? | a screenshot of each address on the site, outlined in red, plus the agent's step-by-step trace |
| Is it connected to other sites? | `address_index.json` / `GET /v1/addresses/:address` — sites sharing a wallet likely share an operator |
| Is it still up? | `status` (`ok` / `unreachable` / `error`); dead sites still get a low-confidence verdict |

**Results on the 160 targets:** _fill in after the run — sites scanned, scams found, addresses
extracted by network, shared wallets, and notable cases._

---

## Quick start (Docker — recommended)

These URLs are live scam infrastructure. Run inside the container, ideally on a disposable VM or
cloud box behind a VPN — not on a work laptop or corporate network.

```bash
docker build -t scam-hunter .

# Try 5 sites first
docker run --rm --shm-size=1g \
  --security-opt no-new-privileges --cap-drop ALL --memory 4g --pids-limit 512 \
  -e ANTHROPIC_API_KEY \
  -v "$(pwd)/output:/app/output" \
  scam-hunter --urls urls.txt --out output --limit 5

# Full run (resumable: re-run the same command and finished URLs are skipped)
docker run --rm --shm-size=1g \
  --security-opt no-new-privileges --cap-drop ALL --memory 4g --pids-limit 512 \
  -e ANTHROPIC_API_KEY \
  -v "$(pwd)/output:/app/output" \
  scam-hunter --urls urls.txt --out output --concurrency 4
```

Outputs:
- `output/results.json` — one record per URL (the deliverable)
- `output/results.jsonl` — incremental log used for resume
- `output/address_index.json` — each address → the sites showing it (shared wallets = shared operator)
- `output/screenshots/` — landing page per site + each address highlighted in context

### Local (no Docker)
```bash
pip install -r requirements.txt && playwright install chromium
export ANTHROPIC_API_KEY=...
python -m hunter.main --urls urls.txt --out output --limit 5
```

### Options
| flag | default | meaning |
|---|---|---|
| `--concurrency` | 4 | sites processed in parallel (one isolated browser context each) |
| `--max-steps` | 10 | agent actions per site; `0` disables exploration |
| `--nav-timeout` | 30 | seconds for initial load |
| `--site-timeout` | 300 | hard cap per site |
| `--limit` | 0 | only first N URLs |
| `--fresh` | off | ignore previous results |

Env: `ANTHROPIC_API_KEY` (without it the run still completes, using heuristics only and no agent),
`HUNTER_MODEL` (default `claude-sonnet-5-5`), `LOG_LEVEL`.

### Tests
```bash
python -m pytest tests          # address extraction + checksum validation
python tests/smoke_test.py      # full pipeline vs. a local fake scam site (no API key needed)
```
The smoke test serves a fake "exchange" (landing → register → deposit page whose address is
loaded from a JSON API with TRC20/ERC20 tabs) and drives it with a scripted stand-in for the LLM, so
the real browser, agent loop, network capture, extraction and screenshots are all exercised.

```bash
cd api && npm install && npm test   # API tests
```

### Querying results (read-only API)

A small Node.js/Express service over `output/results.json`. It re-reads the file when it changes,
so it can stay up during a scan.

```bash
cd api && npm install
RESULTS_DIR=../output PORT=3000 npm start
```

| endpoint | returns |
|---|---|
| `GET /v1/sites?label=SCAM&status=ok&has_addresses=true&min_confidence=0.8&limit=50&offset=0` | filtered, paginated site summaries |
| `GET /v1/sites/lookup?url=https://example.com` | full record for one site |
| `GET /v1/addresses/:address` | every site showing that address, with context and screenshot (EVM lookups are case-insensitive) |
| `GET /v1/addresses?min_sites=2` | wallets shared across sites, most-shared first |
| `GET /v1/stats` | counts by verdict, status and network; scams with addresses; shared wallets |
| `GET /health` | liveness + number of sites loaded |

Bad parameters return `400` with a JSON `error`; unknown sites or addresses return `404`. It binds to
`127.0.0.1` and is read-only. It doesn't serve screenshot files, only their paths.

Why Node.js: TRM's API services are Node.js, while the crawler stays in Python, where the browser
automation and LLM tooling are strongest. The two only share a file format, so either side can change
independently.

---

## Output format

```json
{
  "url": "https://h5.example-ex.co",
  "final_url": "https://h5.example-ex.co/#/pages/login",
  "status": "ok | unreachable | error",
  "http_status": 200,
  "classification": "SCAM",
  "confidence": 0.92,
  "category": "fake crypto exchange",
  "reasoning": "Brand-lookalike h5 trading app requiring USDT deposits ...",
  "red_flags": ["..."],
  "crypto_addresses": [
    {"address": "T...", "network": "TRON", "asset_hint": "USDT (TRC-20)",
     "sources": ["network_api", "visible_text"], "first_seen_on": "https://.../recharge",
     "context": "Recharge USDT TRC20 Deposit address: T..."}
  ],
  "low_confidence_candidates": [],
  "screenshots": ["output/screenshots/..._landing.png", "output/screenshots/..._TXXXXXXXXXXX.png"],
  "exploration": {"steps": ["step 0: ... -> click#4:ok", "..."], "persona_email": "lucas.xxxx@mailinator.com"},
  "error": null,
  "elapsed_s": 41.2
}
```

---

## Architecture

```
urls.txt ─► orchestrator (asyncio, semaphore, resumable JSONL)
              │  per URL: fresh, isolated browser context
              ▼
        ┌─ load ── settle (networkidle + delay) ── harvest ─┐
        │                                                    │
        │   harvest = snapshot DOM (all frames, input values, │
        │   local/sessionStorage) + captured network bodies   │
        │   → address extractor (regex + checksums)           │
        │   → screenshot each new address, highlighted        │
        ▼                                                    │
   classifier (heuristic signals + Claude) ─► SCAM or unsure?│
                                              │ yes          │
                                              ▼              │
                        explorer agent: observe → decide → act ──┘ (harvest after every step)
                                              │
                                              ▼
                              re-classify with what the agent saw
                                              ▼
                                       results.json
```

| module | role |
|---|---|
| `hunter/main.py` | CLI, concurrency, per-site timeouts, resume, final JSON |
| `hunter/browser.py` | Playwright contexts, mobile emulation, network capture, snapshots, screenshots |
| `hunter/extract.py` | address regexes + Base58Check / Bech32(m) validation, exclusion list, source tracking |
| `hunter/classify.py` | heuristic signals + LLM verdict (JSON), fallback when LLM unavailable |
| `hunter/agent.py` | LLM browser agent with a whitelisted action space and burner persona |
| `hunter/llm.py` | Anthropic client wrapper with retries and JSON parsing |

### How addresses are found
1. **Everywhere, not just visible text.** Each harvest scans visible text, full HTML of every frame,
   live `input.value`s (copy-to-clipboard boxes set by JS don't appear in HTML), local/sessionStorage,
   and the bodies of every XHR/fetch response. Fake exchanges usually fetch the deposit address
   from a JSON API, so network capture often finds addresses for networks the UI hasn't shown yet.
2. **Checksums, not just regex.** BTC legacy/P2SH and TRON addresses are Base58Check-verified with
   the right version byte; bech32/bech32m checksums are verified for `bc1` addresses. This removes
   most false positives from hashes, IDs and minified JS.
3. **Known non-targets excluded** — USDT/USDC token contracts, WETH, zero/burn addresses.
4. **Confidence by source.** Addresses seen only inside JavaScript bundles go to
   `low_confidence_candidates` (libraries embed contract/router addresses); anything seen in the
   page, inputs or API responses is reported.
5. **Asset hints** from surrounding text (e.g. "USDT TRC20", "BEP20") since an `0x` address alone
   doesn't say ETH vs. ERC-20 USDT vs. BSC.

### The explorer agent
A small observe → decide → act loop rather than a heavy framework:
- **Observe:** URL, visible-text excerpt, and a numbered list of interactive elements (tagged in the DOM with `data-hid`).
- **Decide:** Claude returns JSON `{"thought", "actions": [...]}` — it can batch form fills but only one click per turn.
- **Act:** only `click / fill / select / goto(same-site) / back / scroll / done`.
- **Harvest after every step**, so any address the agent passes by is captured even if it doesn't notice.
- A **burner persona** (random username, mailinator email, generated password, 6-digit fund PIN, 555 phone number) is used for sign-up/login flows.
- Prompted with the common scam funnel (register → login → recharge → pick coin → pick network) in several languages, and told to switch network tabs after the first address to collect the rest.

### Classification
Heuristic signals (brand-lookalike domain, throwaway TLD, h5/wap template, scam phrases in
English/Chinese) are always computed and passed to Claude as evidence, not used as the decision.
Sites that look like scams or are uncertain (confidence < 0.75) get explored, then re-classified
with what was behind the login wall.

---

## What counts as a scam (assumptions)

**SCAM:** fake exchanges/trading platforms; investment/HYIP/Ponzi schemes (guaranteed or fixed
daily returns, VIP tiers, referral commissions); pig-butchering platforms; fake cloud-mining/staking/
"AI quant" bots; phishing or brand impersonation (exchanges, wallets, Tesla, OpenAI, credit unions);
wallet drainers and fake airdrops/claim pages; task/order-grabbing shops that require USDT top-ups;
fake fund-recovery services; rug-pull meme-token sites.

**NOT_SCAM:** legitimate businesses, real exchanges on official domains, ordinary shops/blogs with
no deceptive financial claims, generic parked pages with no other evidence.

**Unreachable sites:** still classified (from the URL/domain and any partial content) so every URL
gets a label, but `status` is `unreachable` and confidence is capped low. A brand-lookalike,
crypto-themed throwaway domain leans SCAM; an unremarkable one leans NOT_SCAM.

---

## Security considerations

The core risk is an AI agent operating a browser on hostile websites, so it's treated as an
untrusted workload in a disposable sandbox with least privilege at every layer.

- **Where it ran:** a dedicated, snapshotted Linux VM (reverted after each run) on NAT networking with
  shared clipboard/folders disabled, egressing through a VPN with a kill switch, so targets never see
  the operator's IP.
- **Isolation:** runs in a container as a non-root user with all capabilities dropped,
  `no-new-privileges`, memory and PID limits; the only writable mount is `output/`.
- **Browser hygiene:** a fresh browser context per site (no shared cookies/storage), downloads
  disabled, service workers blocked, no permissions granted, non-HTTP schemes (`tg://`, wallet deep
  links, `file://`) aborted, popups forced into the same tab.
- **Prompt injection:** page content is wrapped and labeled as untrusted; the agent can only emit a
  small whitelisted action set; `goto` is restricted to the same site; no file upload, wallet
  connection or seed-phrase actions exist. The worst a malicious page can do is waste steps.
- **No real data:** only generated persona values are ever typed.
- **Secrets:** the LLM key is a dedicated, revocable key with a spending cap, passed by env and never
  written to disk or baked into the image. In production it would be fetched at runtime from Vault or
  GCP Secret Manager as a short-lived, scoped credential.

## What I prioritized and what I cut

TRM ranked classification accuracy and address completeness highest, so that's where the time went:
1. **Address completeness:** scanning network responses and input values, not just visible text;
   an agent that gets past sign-up; collecting every network tab, not just the first address.
2. **Accuracy:** checksum validation to keep false positives out; a written scam definition the
   classifier is held to; re-classifying after exploration instead of judging a login wall.
3. **Security:** sandboxing first, because the system visits malicious sites by design.
4. **Extras:** screenshots and the address index were cheap given the above; the API is a thin layer.

Cut on purpose, with reasons:
- **SMS and email verification:** needs real phone numbers or inbox automation; sites that require it
  are recorded as dead ends in the agent trace.
- **CAPTCHAs:** deliberately not solved; noted in the trace.
- **QR-code decoding:** most addresses here are also present as text or in API responses; first on the list below.
- **Wallet-connect drainers:** would need an injected fake wallet; out of scope for 48 hours.

## Alternatives considered
- **Plain HTTP fetch + regex** — fast, but most targets are JS single-page apps and hide addresses behind login.
- **Off-the-shelf browser agents (browser-use, computer-use with screenshots)** — more general, but slower,
  costlier per step, and harder to constrain. A DOM-indexed action list is cheaper and more auditable.
- **Vision-first agent** — better on canvas-rendered UIs; kept as a future fallback.
- **Pure-ML classifier** — no labelled data in 48h; an LLM with explicit criteria plus heuristics gives explainable verdicts.

## Production path (Kafka · GCP · AlloyDB)

v1 is a batch CLI on purpose. The pieces map onto a streaming deployment without a rewrite:

```
  candidate URLs                 crawler workers                    results
 (reports, feeds,  ──► Kafka ──► (this code, one site per ──► Kafka ──► AlloyDB  (sites, addresses,
  CT logs, ...)       topic:      message; GKE or Cloud Run   topic:      verdicts, evidence)
                      urls.in     jobs in an isolated VPC)    sites.out   GCS      (screenshots, HTML)
```

- **Unit of work = one site.** `analyze()` already takes one URL and returns one self-contained record,
  so it becomes a Kafka consumer with no structural change; `results.jsonl` becomes a producer.
- **AlloyDB schema (sketch):** `sites(url, verdict, confidence, category, status, scanned_at)`,
  `addresses(address, network)` and a join table `site_addresses(site_id, address_id, source, context,
  screenshot_uri)`. The address → many-sites join is the attribution signal (see `address_index.json`).
- **Evidence** (screenshots, HTML, captured API responses) goes to GCS; AlloyDB stores URIs.
- **Isolation:** crawler workers run in their own VPC/project with egress only to the internet, the
  LLM API and Kafka — never to internal services.
- **Re-scans:** scam sites rotate deposit addresses, so sites are re-queued on a schedule and new
  addresses are appended with timestamps rather than overwritten.
- **Analytics:** verdicts and the address index also land in BigQuery for trend questions, e.g.
  which scam kits, TLDs or networks are growing week over week.
- **Multi-region crawling:** many scam sites cloak by visitor country (pig-butchering platforms often
  target specific regions). Running workers from more than one region and diffing what each sees catches
  content a single vantage point misses, and makes "inactive" verdicts more trustworthy.
- **SLOs and observability:** the per-site `status`, `error` and `elapsed_s` fields become metrics:
  scan success rate, p95 time per site, agent steps per site, addresses found per confirmed scam,
  and LLM cost per site. An alert fires when the success rate drops, which usually means a new
  blocking technique.
- Playwright has the same API in Node.js, so the browser layer could move into a Node service if that
  fits the team better; extraction and classification would stay in Python.

## What's unique
- **Cross-site address index** (`output/address_index.json`): addresses inverted to the sites that show
  them. One deposit wallet on several "different" exchanges links them to a single operator.
- Network-response harvesting: catches addresses from APIs before (or without) the UI showing them.
- Checksum-validated extraction with source tracking and a confidence split.
- Mobile emulation for `h5.`/`m.`/`/wap` templates that render blank on desktop.
- Every address screenshot is taken at the moment it's found, outlined in red, in context.
- Resumable, crash-tolerant batch runs; each site has a hard timeout and always produces a record.

## What I'd do with more time
- **QR-code decoding** of deposit images (pyzbar/zxing) — some sites only show a QR.
- **Inbox automation** for mailinator to complete email-verification steps; SMS is out of scope.
- **Template fingerprinting:** many targets share the same scam kit (same JS bundles / API paths
  like `/api/user/recharge`). Cluster sites by kit and replay the known path to the deposit API directly.
- **EIP-55 checksum** validation for mixed-case EVM addresses; more chains (SOL, LTC, BNB, XRP).
- **Enrichment:** WHOIS/domain age, TLS cert issuance, hosting ASN, and on-chain lookup of each
  address (balance, first-seen, links to known clusters) to raise confidence and prioritise.
- **Vision fallback** for canvas UIs and CAPTCHAs we shouldn't solve but should report.
- **Evaluation set:** hand-label a sample, measure precision/recall per category, tune the threshold.
- Network-level egress controls (a proxy allowlisting only the target host + the LLM API).

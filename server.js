// Read-only REST API over Scam Hunter output.
//
//   RESULTS_DIR=../output PORT=3000 npm start
//
// The crawler writes results.json; this service re-reads it whenever the file
// changes, so it can stay up while a scan is running or being re-run.

import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const LABELS = new Set(["SCAM", "NOT_SCAM"]);
const STATUSES = new Set(["ok", "unreachable", "error"]);
const MAX_LIMIT = 200;

// EVM addresses are case-insensitive; BTC base58 and TRON are case-sensitive.
const addrKey = (a) => (/^0x/i.test(a) ? a.toLowerCase() : a);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** Loads results.json lazily and rebuilds lookups only when the file changes. */
export function createStore(dir) {
  const file = path.join(dir, "results.json");
  let cache = { mtimeMs: -1, sites: [], byUrl: new Map(), byAddress: new Map(), loadedAt: null };

  function build(sites) {
    const byUrl = new Map(sites.map((s) => [s.url, s]));
    const byAddress = new Map();
    for (const s of sites) {
      for (const a of s.crypto_addresses ?? []) {
        const key = addrKey(a.address);
        if (!byAddress.has(key)) {
          byAddress.set(key, { address: a.address, network: a.network, asset_hints: new Set(), sites: [] });
        }
        const entry = byAddress.get(key);
        entry.asset_hints.add(a.asset_hint);
        entry.sites.push({
          url: s.url,
          classification: s.classification,
          confidence: s.confidence,
          first_seen_on: a.first_seen_on,
          context: a.context,
          screenshot: (s.screenshots ?? []).find((p) => p.includes(a.address.slice(0, 12))) ?? null,
        });
      }
    }
    return { byUrl, byAddress };
  }

  return function load() {
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      throw new HttpError(503, `no results yet at ${file}; run the crawler first`);
    }
    if (stat.mtimeMs !== cache.mtimeMs) {
      const sites = JSON.parse(fs.readFileSync(file, "utf8"));
      cache = { mtimeMs: stat.mtimeMs, sites, ...build(sites), loadedAt: new Date().toISOString() };
    }
    return cache;
  };
}

const summarize = (s) => ({
  url: s.url,
  classification: s.classification,
  confidence: s.confidence,
  category: s.category,
  status: s.status,
  address_count: (s.crypto_addresses ?? []).length,
});

const serializeAddress = (e) => ({
  address: e.address,
  network: e.network,
  asset_hints: [...e.asset_hints].sort(),
  site_count: e.sites.length,
  sites: e.sites,
});

function parseQuery(q) {
  const out = {};
  if (q.label !== undefined) {
    const label = String(q.label).toUpperCase();
    if (!LABELS.has(label)) throw new HttpError(400, "label must be SCAM or NOT_SCAM");
    out.label = label;
  }
  if (q.status !== undefined) {
    if (!STATUSES.has(q.status)) throw new HttpError(400, "status must be ok, unreachable or error");
    out.status = q.status;
  }
  if (q.has_addresses !== undefined) {
    if (!["true", "false"].includes(q.has_addresses)) throw new HttpError(400, "has_addresses must be true or false");
    out.hasAddresses = q.has_addresses === "true";
  }
  if (q.min_confidence !== undefined) {
    const c = Number(q.min_confidence);
    if (!Number.isFinite(c) || c < 0 || c > 1) throw new HttpError(400, "min_confidence must be between 0 and 1");
    out.minConfidence = c;
  }
  const limit = q.limit === undefined ? 50 : Number(q.limit);
  const offset = q.offset === undefined ? 0 : Number(q.offset);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) throw new HttpError(400, `limit must be 1-${MAX_LIMIT}`);
  if (!Number.isInteger(offset) || offset < 0) throw new HttpError(400, "offset must be a non-negative integer");
  return { ...out, limit, offset };
}

export function createApp({ resultsDir }) {
  const load = createStore(resultsDir);
  const app = express();
  app.disable("x-powered-by");

  app.get("/health", (_req, res) => {
    let sites = null;
    try {
      sites = load().sites.length;
    } catch {
      /* no results yet is still "up" */
    }
    res.json({ ok: true, sites });
  });

  // List sites with filters + pagination.
  app.get("/v1/sites", (req, res) => {
    const f = parseQuery(req.query);
    const items = load().sites.filter(
      (s) =>
        (f.label === undefined || s.classification === f.label) &&
        (f.status === undefined || s.status === f.status) &&
        (f.minConfidence === undefined || (s.confidence ?? 0) >= f.minConfidence) &&
        (f.hasAddresses === undefined || ((s.crypto_addresses ?? []).length > 0) === f.hasAddresses),
    );
    res.json({ total: items.length, limit: f.limit, offset: f.offset,
               items: items.slice(f.offset, f.offset + f.limit).map(summarize) });
  });

  // Full record for one site. URL goes in the query string because it contains slashes.
  app.get("/v1/sites/lookup", (req, res) => {
    if (!req.query.url) throw new HttpError(400, "url query parameter is required");
    const site = load().byUrl.get(String(req.query.url));
    if (!site) throw new HttpError(404, "site not found");
    res.json(site);
  });

  // Every site showing this address: the attribution question.
  app.get("/v1/addresses/:address", (req, res) => {
    const entry = load().byAddress.get(addrKey(req.params.address));
    if (!entry) throw new HttpError(404, "address not found");
    res.json(serializeAddress(entry));
  });

  // Addresses seen on more than one site (likely the same operator).
  app.get("/v1/addresses", (req, res) => {
    const minSites = req.query.min_sites === undefined ? 1 : Number(req.query.min_sites);
    if (!Number.isInteger(minSites) || minSites < 1) throw new HttpError(400, "min_sites must be a positive integer");
    const items = [...load().byAddress.values()]
      .filter((e) => e.sites.length >= minSites)
      .sort((a, b) => b.sites.length - a.sites.length)
      .map(serializeAddress);
    res.json({ total: items.length, items });
  });

  app.get("/v1/stats", (_req, res) => {
    const { sites, byAddress, loadedAt } = load();
    const count = (fn) => sites.reduce((m, s) => ((m[fn(s)] = (m[fn(s)] ?? 0) + 1), m), {});
    const addresses = [...byAddress.values()];
    res.json({
      loaded_at: loadedAt,
      sites: sites.length,
      by_classification: count((s) => s.classification),
      by_status: count((s) => s.status),
      scams_with_addresses: sites.filter((s) => s.classification === "SCAM" && s.crypto_addresses?.length).length,
      addresses: addresses.length,
      addresses_by_network: addresses.reduce((m, e) => ((m[e.network] = (m[e.network] ?? 0) + 1), m), {}),
      shared_addresses: addresses.filter((e) => e.sites.length > 1).length,
    });
  });

  app.use((_req, _res, next) => next(new HttpError(404, "not found")));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    const status = err.status ?? 500;
    if (status >= 500 && status !== 503) console.error(err);
    res.status(status).json({ error: status === 500 ? "internal error" : err.message });
  });
  return app;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const resultsDir = path.resolve(process.env.RESULTS_DIR ?? path.join(here, "..", "output"));
  const port = Number(process.env.PORT ?? 3000);
  createApp({ resultsDir }).listen(port, "127.0.0.1", () => {
    console.log(`scam-hunter API on http://127.0.0.1:${port} (results: ${resultsDir})`);
  });
}

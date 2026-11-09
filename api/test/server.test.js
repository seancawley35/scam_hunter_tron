import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp } from "../server.js";

const SHARED = "TA4Y62o6YC2Zsck9rZVGTvqW1AQ7X9zTnj";
const ETH = "0x52908400098527886E0F7030069857D2E4169EE7";
const addr = (address, network, asset_hint) => ({ address, network, asset_hint, context: "deposit", first_seen_on: "x" });

const sites = [
  { url: "https://a-ex.top", classification: "SCAM", confidence: 0.95, category: "fake exchange", status: "ok",
    crypto_addresses: [addr(SHARED, "TRON", "USDT (TRC-20)"), addr(ETH, "EVM", "USDT (ERC-20)")],
    screenshots: [`out/a__${SHARED.slice(0, 12)}.png`] },
  { url: "https://b-ex.top", classification: "SCAM", confidence: 0.9, category: "fake exchange", status: "ok",
    crypto_addresses: [addr(SHARED, "TRON", "USDT (TRC-20)")], screenshots: [] },
  { url: "https://bakery.example", classification: "NOT_SCAM", confidence: 0.85, category: "legitimate",
    status: "ok", crypto_addresses: [], screenshots: [] },
  { url: "https://gone.xyz", classification: "SCAM", confidence: 0.4, category: "fake exchange",
    status: "unreachable", crypto_addresses: [], screenshots: [] },
];

let server, base, dir;

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunter-api-"));
  fs.writeFileSync(path.join(dir, "results.json"), JSON.stringify(sites));
  server = createApp({ resultsDir: dir }).listen(0);
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const get = async (p) => {
  const r = await fetch(base + p);
  return { status: r.status, body: await r.json() };
};

test("lists and filters sites", async () => {
  const all = await get("/v1/sites");
  assert.equal(all.body.total, 4);
  const scams = await get("/v1/sites?label=scam&has_addresses=true");
  assert.deepEqual(scams.body.items.map((s) => s.url), ["https://a-ex.top", "https://b-ex.top"]);
  const confident = await get("/v1/sites?min_confidence=0.9&limit=1");
  assert.equal(confident.body.total, 2);
  assert.equal(confident.body.items.length, 1);
});

test("rejects bad query params", async () => {
  assert.equal((await get("/v1/sites?label=maybe")).status, 400);
  assert.equal((await get("/v1/sites?limit=5000")).status, 400);
  assert.equal((await get("/v1/sites?min_confidence=2")).status, 400);
});

test("looks up one site", async () => {
  const r = await get("/v1/sites/lookup?url=" + encodeURIComponent("https://a-ex.top"));
  assert.equal(r.status, 200);
  assert.equal(r.body.crypto_addresses.length, 2);
  assert.equal((await get("/v1/sites/lookup?url=https%3A%2F%2Fnope.com")).status, 404);
});

test("address lookup links sites sharing a wallet", async () => {
  const r = await get(`/v1/addresses/${SHARED}`);
  assert.equal(r.body.site_count, 2);
  assert.ok(r.body.sites[0].screenshot.includes(SHARED.slice(0, 12)));
  const evm = await get(`/v1/addresses/${ETH.toLowerCase()}`); // EVM lookup is case-insensitive
  assert.equal(evm.status, 200);
  const shared = await get("/v1/addresses?min_sites=2");
  assert.deepEqual(shared.body.items.map((e) => e.address), [SHARED]);
});

test("stats summarize the run", async () => {
  const { body } = await get("/v1/stats");
  assert.equal(body.sites, 4);
  assert.deepEqual(body.by_classification, { SCAM: 3, NOT_SCAM: 1 });
  assert.equal(body.scams_with_addresses, 2);
  assert.equal(body.shared_addresses, 1);
});

test("unknown route is a JSON 404", async () => {
  const r = await get("/nope");
  assert.equal(r.status, 404);
  assert.equal(r.body.error, "not found");
});

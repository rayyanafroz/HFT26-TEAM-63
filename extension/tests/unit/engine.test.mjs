import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { cleanText, codePointOffsets, loadEngine } from "../../src/engine/engine.js";

const wasm = readFileSync(new URL("../../src/engine/shadowlens_engine.wasm", import.meta.url));
const key = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";

test("the engine finds a key and gives UTF-16 ranges that slice the original text", async () => {
  const engine = await loadEngine(wasm, { salt_hex: "11".repeat(32) });
  const text = `\u{1F600}\u{1F600} key: ${key} \u{1F680}`;
  const r = engine.analyze(text);
  assert.equal(r.findings.length, 1);
  const [f] = r.findings;
  assert.equal(f.rule_id, "SEC_OPENAI_KEY");
  assert.equal(text.slice(...f.ranges[0]), key);
  assert.deepEqual(f.spans[0], [8, 8 + key.length]); // code points: each emoji counts once
  assert.ok(!r.redacted_text.includes(key) && !r.safe_to_send);
  assert.equal(f.masked_preview.length < 20, true);
});

test("the salt changes the hash, as it must per install", async () => {
  const a = (await loadEngine(wasm, { salt_hex: "11".repeat(32) })).analyze(key).findings[0].hash12;
  const b = (await loadEngine(wasm, { salt_hex: "22".repeat(32) })).analyze(key).findings[0].hash12;
  assert.notEqual(a, b);
});

test("lone surrogates become '?' like the reference, and clean text is safe", async () => {
  const engine = await loadEngine(wasm);
  assert.equal(cleanText("a\uD800b\uDC00c😀"), "a?b?c😀");
  assert.equal(engine.analyze("a\uD800b").safe_to_send, true);
  assert.equal(engine.analyze("").safe_to_send, true);
  assert.deepEqual(codePointOffsets("a\u{1F600}b"), [0, 1, 3, 4]);
});

test("bad settings are refused", async () => {
  await assert.rejects(loadEngine(wasm, { salt_hex: "zz" }), /settings/);
});

test("a typical prompt is analyzed in well under a frame once warm", async () => {
  const engine = await loadEngine(wasm);
  engine.warm();
  const prompt = `Here is my config, why does it fail?\nOPENAI_API_KEY=${key}\nmodel=gpt-4o\nthanks, jordan@acme-demo.invalid`;
  engine.analyze(prompt);
  const start = performance.now();
  for (let i = 0; i < 100; i++) engine.analyze(prompt);
  const each = (performance.now() - start) / 100;
  assert.ok(each < 5, `${each.toFixed(2)} ms per prompt`);
});

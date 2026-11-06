// The conformance protocol over the WebAssembly engine, run in Node:
//
//   node extension/tools/adapter.mjs [--settings conformance/build/settings.json] < cases > answers
//
// Used by `python -m conformance.check --cmd "node extension/tools/adapter.mjs ..."` and by the fuzzer
// (with --text-only), so the exact .wasm the extension ships is held to the reference.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadEngine } from "../src/engine/engine.js";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const at = args.indexOf("--settings");
const settings = at >= 0 ? JSON.parse(readFileSync(args[at + 1], "utf8")) : {};
const wasm = readFileSync(join(here, "..", "src", "engine", "shadowlens_engine.wasm"));
const engine = await loadEngine(wasm, settings);

// Split on "\n" only: readline would also split on U+2028 and U+2029, which JSON leaves unescaped.
async function* lines(stream) {
  let pending = "";
  stream.setEncoding("utf8");
  for await (const chunk of stream) {
    pending += chunk;
    let cut;
    while ((cut = pending.indexOf("\n")) >= 0) {
      yield pending.slice(0, cut);
      pending = pending.slice(cut + 1);
    }
  }
  if (pending) yield pending;
}

for await (const line of lines(process.stdin)) {
  if (!line.trim()) continue;
  const request = JSON.parse(line);
  let reply;
  if (request.op) {
    reply = { id: request.id, error: `op ${request.op} is not available in the WebAssembly build` };
  } else {
    const { findings, redacted_text, safe_to_send, failed } = engine.analyze(request.text);
    // The contract has no UTF-16 ranges; they are a convenience of the JavaScript wrapper.
    reply = { id: request.id, findings: findings.map(({ ranges, ...f }) => f), redacted_text, safe_to_send, failed };
  }
  process.stdout.write(JSON.stringify(reply) + "\n");
}

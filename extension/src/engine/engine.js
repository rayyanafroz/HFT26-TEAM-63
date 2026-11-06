// The detection engine (Rust, compiled to WebAssembly) behind a small JavaScript API.
// Runs unchanged in the extension's service worker and in Node (tests, the conformance adapter).
//
//   const engine = await loadEngine(wasmBytesOrUrl, { salt_hex: "..." });
//   const result = engine.analyze(text);
//
// `result.findings[i].spans` are Unicode code point offsets (the engine's contract);
// `result.findings[i].ranges` are the same spans as UTF-16 offsets, which is what JavaScript strings,
// DOM ranges and `String.prototype.slice` use.

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

// Lone surrogates cannot be encoded as UTF-8. The reference turns each into "?" (one character, so
// positions do not move); do the same before the text reaches the engine.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

export function cleanText(text) {
  return text.replace(LONE_SURROGATE, "?");
}

/** For every code point index, its UTF-16 offset (one extra entry for the end). */
export function codePointOffsets(text) {
  const offsets = [];
  let unit = 0;
  for (const ch of text) {
    offsets.push(unit);
    unit += ch.length;
  }
  offsets.push(unit);
  return offsets;
}

async function toModule(source) {
  if (source instanceof WebAssembly.Module) return source;
  if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) return WebAssembly.compile(source);
  const response = source instanceof Response ? source : await fetch(source);
  if (!response.ok) throw new Error(`could not load the engine (${response.status})`);
  return WebAssembly.compile(await response.arrayBuffer());
}

export async function loadEngine(source, settings = {}) {
  const module = await toModule(source);
  const instance = await WebAssembly.instantiate(module, {});
  const x = instance.exports;

  const put = (bytes) => {
    const ptr = x.sl_alloc(bytes.length);
    new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  };

  const settingsBytes = encoder.encode(JSON.stringify(settings));
  const sptr = put(settingsBytes);
  const status = x.sl_init(sptr, settingsBytes.length);
  x.sl_free(sptr, settingsBytes.length);
  if (status !== 0) throw new Error(status === 1 ? "the engine settings are not valid" : "a detector pattern did not compile");

  function analyze(input) {
    const text = cleanText(String(input ?? ""));
    const bytes = encoder.encode(text);
    const ptr = put(bytes);
    let rptr;
    let rlen;
    try {
      rptr = x.sl_analyze(ptr, bytes.length);
      rlen = x.sl_result_len();
    } finally {
      x.sl_free(ptr, bytes.length);
    }
    // Copy out before freeing; memory.buffer may have been replaced if the module's memory grew.
    const json = decoder.decode(new Uint8Array(x.memory.buffer, rptr, rlen).slice());
    x.sl_free(rptr, rlen);
    const result = JSON.parse(json);
    if (result.error) throw new Error(`engine: ${result.error}`);
    if (result.findings.length) {
      const offsets = codePointOffsets(text);
      for (const f of result.findings) f.ranges = f.spans.map(([a, b]) => [offsets[a], offsets[b]]);
    }
    return result;
  }

  /** Compile every pattern now instead of on first use (they compile lazily, as needed). */
  function warm() {
    x.sl_warm();
  }

  return { analyze, warm };
}

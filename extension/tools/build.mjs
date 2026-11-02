// Builds the loadable extension into extension/dist (load it at chrome://extensions, "Load unpacked").
//
//   node tools/build.mjs            build
//   node tools/build.mjs --watch    rebuild on change
//   node tools/build.mjs --test     build dist-test for the end-to-end tests
//
// The engine (src/engine/shadowlens_engine.wasm) is built separately with `node tools/build-engine.mjs`.

import * as esbuild from "esbuild";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

import { SITES, matchPatterns } from "../src/shared/sites.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// --test builds into dist-test with the panel's shadow root open, so end-to-end tests can reach it.
const testBuild = process.argv.includes("--test");
const dist = join(root, testBuild ? "dist-test" : "dist");
const src = (p) => join(root, "src", p);
const out = (p) => join(dist, p);
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const { key } = JSON.parse(readFileSync(join(root, "static", "extension-key.json"), "utf8"));

const wasm = src("engine/shadowlens_engine.wasm");
if (!existsSync(wasm)) {
  console.error("The engine is missing: run `node tools/build-engine.mjs` first (needs Rust).");
  process.exit(1);
}

function manifest() {
  const hosts = matchPatterns();
  return {
    manifest_version: 3,
    name: "Shadow Lens",
    version: pkg.version,
    description: "Stops API keys, passwords and personal data before they are pasted, sent or uploaded to an AI chat. Everything is checked on your device.",
    minimum_chrome_version: "116",
    key,
    icons: { 16: "icons/icon-16.png", 32: "icons/icon-32.png", 48: "icons/icon-48.png", 128: "icons/icon-128.png" },
    action: { default_title: "Shadow Lens", default_popup: "popup/popup.html", default_icon: { 16: "icons/icon-16.png", 32: "icons/icon-32.png" } },
    options_page: "options/options.html",
    background: { service_worker: "background.js", type: "module" },
    content_scripts: [{ matches: hosts, js: ["content/content.js"], css: ["content/content.css"], run_at: "document_idle" }],
    permissions: ["storage", "scripting", "offscreen", "nativeMessaging", "clipboardWrite"],
    host_permissions: hosts,
    content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" },
  };
}

// ---- icons: a lens (teal ring) with a dot, drawn here so the build needs no image tools ----

function crc32(bytes) {
  let c, crc = 0xffffffff;
  for (const b of bytes) {
    c = (crc ^ b) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function png(size, pixel) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) raw.set(pixel(x + 0.5, y + 0.5, size), y * (size * 4 + 1) + 1 + x * 4);
  }
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type), data]);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", header), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

function lens(x, y, size) {
  const c = size / 2;
  const d = Math.hypot(x - c, y - c) / (size / 2);
  const cover = (inner, outer) => Math.max(0, Math.min(1, (outer - d) * size / 2)) * Math.max(0, Math.min(1, (d - inner) * size / 2));
  const tile = Math.max(0, Math.min(1, (1 - d) * size / 2 + 0.5)); // round night tile
  const ring = cover(0.5, 0.74);
  const dot = Math.max(0, Math.min(1, (0.22 - d) * size / 2 + 0.5));
  const teal = [63, 193, 184];
  const night = [14, 21, 27];
  const mix = Math.max(ring, dot);
  const rgb = night.map((n, i) => Math.round(n + (teal[i] - n) * mix));
  return [...rgb, Math.round(255 * tile)];
}

async function build() {
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(dist, { recursive: true });
  const common = { bundle: true, target: ["chrome116"], legalComments: "none", logLevel: "warning", sourcemap: false,
    define: { __SHADOWLENS_TEST__: String(testBuild) } };
  await Promise.all([
    esbuild.build({ ...common, entryPoints: [src("content/main.js")], outfile: out("content/content.js"), format: "iife" }),
    esbuild.build({ ...common, entryPoints: [src("background/service-worker.js")], outfile: out("background.js"), format: "esm" }),
    esbuild.build({ ...common, entryPoints: [src("popup/popup.js")], outfile: out("popup/popup.js"), format: "esm" }),
    esbuild.build({ ...common, entryPoints: [src("options/options.js")], outfile: out("options/options.js"), format: "esm" }),
    esbuild.build({ ...common, entryPoints: [src("offscreen/offscreen.js")], outfile: out("offscreen/offscreen.js"), format: "esm", minify: true }),
  ]);
  cpSync(src("content/content.css"), out("content/content.css"));
  for (const page of ["popup/popup.html", "popup/popup.css", "options/options.html", "options/options.css", "offscreen/offscreen.html", "pages/pages.css"]) {
    cpSync(src(page), out(page));
  }
  cpSync(join(root, "node_modules/pdfjs-dist/build/pdf.worker.min.mjs"), out("offscreen/pdf.worker.min.mjs"));
  cpSync(wasm, out("engine/shadowlens_engine.wasm"));
  cpSync(join(root, "..", "ui", "fonts"), out("fonts"), { recursive: true });
  mkdirSync(out("icons"));
  for (const size of [16, 32, 48, 128]) writeFileSync(out(`icons/icon-${size}.png`), png(size, lens));
  writeFileSync(out("manifest.json"), JSON.stringify(manifest(), null, 2) + "\n");
  console.log(`built ${dist} (${SITES.length} sites)`);
}

await build();
if (process.argv.includes("--watch")) {
  const { watch } = await import("node:fs");
  let timer = null;
  watch(join(root, "src"), { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(() => build().catch((e) => console.error(e.message)), 150);
  });
  console.log("watching src/ ...");
}

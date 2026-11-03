// Builds the landing page into site/dist (static files; host anywhere, for example GitHub Pages).
//
//   node site/build.mjs            build
//   node site/build.mjs --serve    build, then serve it on http://localhost:8000
//
// Needs the engine built first: node extension/tools/build-engine.mjs (and `npm install` in extension/).

import { createRequire } from "node:module";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
// --out <folder>: build somewhere else (for `railway up`, which skips anything this repo's .gitignore lists)
const outArg = process.argv.indexOf("--out");
const dist = outArg > 0 ? resolve(process.argv[outArg + 1]) : join(here, "dist");
const wasm = join(repo, "extension", "src", "engine", "shadowlens_engine.wasm");
const esbuild = createRequire(join(repo, "extension", "package.json"))("esbuild");

if (!existsSync(wasm)) {
  console.error("The engine is missing: run `node extension/tools/build-engine.mjs` first (needs Rust).");
  process.exit(1);
}

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });
await esbuild.build({
  entryPoints: [join(here, "src", "demo.js")], bundle: true, format: "esm", target: ["chrome116", "firefox120", "safari17"],
  outfile: join(dist, "demo.js"), minify: true, legalComments: "none", logLevel: "warning",
});
// --static: for hosts that serve files themselves (Vercel, Netlify, GitHub Pages): no server, and the
// headers the server would send go into vercel.json instead.
const staticHost = process.argv.includes("--static");
for (const file of staticHost ? ["index.html", "styles.css"] : ["index.html", "styles.css", "server.mjs", "package.json"]) cpSync(join(here, "src", file), join(dist, file));
if (staticHost) {
  // The same header list the server sends, read from the server's own source so the two cannot drift.
  const source = readFileSync(join(here, "src", "server.mjs"), "utf8");
  const block = source.match(/const SECURITY = (\{[\s\S]*?\n\});/)[1];
  const headers = Function(`"use strict"; return (${block});`)();
  writeFileSync(join(dist, "vercel.json"), JSON.stringify({
    cleanUrls: true,
    headers: [
      { source: "/(.*)", headers: Object.entries(headers).map(([key, value]) => ({ key, value })) },
      { source: "/(.*)\\.wasm", headers: [{ key: "Content-Type", value: "application/wasm" }, { key: "Cache-Control", value: "public, max-age=3600" }] },
      { source: "/", headers: [{ key: "Cache-Control", value: "no-cache" }] },
    ],
  }, null, 2) + "\n");
}
cpSync(join(here, "src", "assets"), join(dist, "assets"), { recursive: true });
cpSync(join(repo, "ui", "fonts"), join(dist, "fonts"), { recursive: true });
cpSync(wasm, join(dist, "shadowlens_engine.wasm"));
console.log(`built ${dist}`);

if (process.argv.includes("--serve")) {
  // The same server that runs in production, so what you see here is what is deployed.
  const { spawn } = await import("node:child_process");
  spawn(process.execPath, [join(dist, "server.mjs")], { stdio: "inherit", env: { ...process.env, PORT: process.env.PORT ?? "8000" } });
}

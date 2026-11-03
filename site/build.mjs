// Builds the landing page into site/dist (static files; host anywhere, for example GitHub Pages).
//
//   node site/build.mjs            build
//   node site/build.mjs --serve    build, then serve it on http://localhost:8000
//
// Needs the engine built first: node extension/tools/build-engine.mjs (and `npm install` in extension/).

import { createRequire } from "node:module";
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const dist = join(here, "dist");
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
for (const file of ["index.html", "styles.css"]) cpSync(join(here, "src", file), join(dist, file));
cpSync(join(here, "src", "assets"), join(dist, "assets"), { recursive: true });
cpSync(join(repo, "ui", "fonts"), join(dist, "fonts"), { recursive: true });
cpSync(wasm, join(dist, "shadowlens_engine.wasm"));
console.log(`built ${dist}`);

if (process.argv.includes("--serve")) {
  const types = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".wasm": "application/wasm", ".png": "image/png", ".woff2": "font/woff2", ".txt": "text/plain" };
  createServer(async (req, res) => {
    let path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^(\.\.[/\\])+/, "");
    if (path.endsWith("/")) path += "index.html";
    let body;
    try {
      body = await readFile(join(dist, path));
    } catch {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": types[extname(path)] ?? "application/octet-stream" }).end(body);
  }).listen(8000, () => console.log("http://localhost:8000"));
}

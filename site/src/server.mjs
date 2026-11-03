// A tiny static file server for the landing page: no dependencies, Node 20+.
//   node server.mjs            listens on $PORT (default 8000)
// Serves only known file types from this folder, with compression, caching and security headers.

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompress, gzip } from "node:zlib";
import { promisify } from "node:util";

const root = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT ?? 8000);
const brotli = promisify(brotliCompress);
const gz = promisify(gzip);

const TYPES = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm", ".png": "image/png", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8", ".svg": "image/svg+xml",
};
const COMPRESSIBLE = new Set([".html", ".css", ".js", ".txt", ".svg"]);   // .wasm and .woff2 are already dense; brotli of the wasm costs more than it saves per request
const SECURITY = {
  "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  "cross-origin-opener-policy": "same-origin",
};
const cache = new Map();            // path -> { body, type, etag, gzip, br }

async function load(path) {
  if (cache.has(path)) return cache.get(path);
  const ext = extname(path);
  if (!TYPES[ext]) return null;
  const file = join(root, path);
  if (!file.startsWith(root + sep)) return null;
  let body;
  try {
    if (!(await stat(file)).isFile()) return null;
    body = await readFile(file);
  } catch {
    return null;
  }
  const entry = { body, type: TYPES[ext], etag: `"${body.length.toString(16)}-${Buffer.from(body.subarray(0, 64)).reduce((h, b) => (h * 31 + b) >>> 0, 7).toString(16)}"`, ext };
  if (COMPRESSIBLE.has(ext)) [entry.gzip, entry.br] = await Promise.all([gz(body), brotli(body)]);
  cache.set(path, entry);
  return entry;
}

function send(res, status, headers, body) {
  res.writeHead(status, { ...SECURITY, ...headers });
  res.end(body);
}

createServer(async (req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, { allow: "GET, HEAD" }, "method not allowed");
  let path;
  try {
    path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname));
  } catch {
    return send(res, 400, {}, "bad request");
  }
  if (path === "/healthz") return send(res, 200, { "content-type": "text/plain" }, "ok");
  if (path.endsWith(sep) || path === "/") path = join(path, "index.html");
  if (path.includes("\0") || path.split(sep).some((part) => part.startsWith("."))) return send(res, 404, { "content-type": "text/plain" }, "not found");
  const entry = await load(path);
  if (!entry) return send(res, 404, { "content-type": "text/plain" }, "not found");
  const headers = {
    "content-type": entry.type, etag: entry.etag, vary: "accept-encoding",
    // The page changes when redeployed; the big static files are safe to keep for an hour.
    "cache-control": entry.ext === ".html" ? "no-cache" : "public, max-age=3600",
  };
  if (req.headers["if-none-match"] === entry.etag) return send(res, 304, headers, null);
  let body = entry.body;
  const accepts = String(req.headers["accept-encoding"] ?? "");
  if (entry.br && /\bbr\b/.test(accepts)) [body, headers["content-encoding"]] = [entry.br, "br"];
  else if (entry.gzip && /\bgzip\b/.test(accepts)) [body, headers["content-encoding"]] = [entry.gzip, "gzip"];
  headers["content-length"] = body.length;
  send(res, 200, headers, req.method === "HEAD" ? null : body);
}).listen(port, "0.0.0.0", () => console.log(`Shadow Lens site on http://0.0.0.0:${port}`));

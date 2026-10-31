// The only module that talks to the backend. Screens never call fetch directly.
//
// Base URL: same origin by default (FastAPI serves ui/ at /, port 8787 unless SHADOWLENS_PORT is changed).
// To point the UI at another server set window.SHADOWLENS_API_BASE before this module loads,
// or add <meta name="shadowlens-api-base" content="http://127.0.0.1:8790"> to index.html.
//
// Mock mode: open the page with ?mock=1. Requests then read ui/mock/<path>.json instead of the network.
//   /api/stats/summary        -> mock/stats_summary.json         (SOT 9.1: drop "/api/", slashes become underscores)
//   /api/alerts/<uuid>/ack    -> mock/alerts_id_ack.json         (id-like segments become "id"; our addition)
// A host page can also set window.SHADOWLENS_MOCK = true before loading this module (used by the hosted preview).
// Query strings are ignored in mock mode. A missing mock file is an error, never a silent success.

const meta = document.querySelector('meta[name="shadowlens-api-base"]');
export const API_BASE = String(window.SHADOWLENS_API_BASE ?? meta?.content ?? "").replace(/\/$/, "");
export const MOCK = window.SHADOWLENS_MOCK === true || new URLSearchParams(window.location.search).get("mock") === "1";

/** One error shape for every failure, so screens can show a message with Retry. */
export class ApiError extends Error {
  constructor(message, { status = 0, path = "" } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;   // 0 = the local service did not respond
    this.path = path;
  }
}

function mockFile(path) {
  const clean = path.split("?")[0].replace(/^\/api\//, "");
  const segs = clean.split("/");
  // resource/{id}[/action]: the segment after these resources is always an id (alerts/<uuid>/ack, providers/openai/sanction)
  const idAfter = ["alerts", "providers", "sources"];
  const name = segs.map((seg, i) => (/^[0-9a-f]{8}-|^\d+$/i.test(seg) || (i === 1 && idAfter.includes(segs[0])) ? "id" : seg)).join("_");
  return new URL(`mock/${name}.json`, document.baseURI).href;
}

function withParams(path, params) {
  if (!params) return path;
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") qs.set(key, String(value));
  }
  const text = qs.toString();
  return text ? `${path}?${text}` : path;
}

async function readJson(response, path) {
  let body = null;
  try { body = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) {
    throw new ApiError(body?.error ?? `The request failed (${response.status}).`, { status: response.status, path });
  }
  return body;
}

async function send(method, path, { params, json, form } = {}) {
  const target = withParams(path, params);
  if (MOCK) {
    try {
      return await readJson(await fetch(mockFile(path)), path);
    } catch (err) {
      if (err instanceof ApiError) throw new ApiError(`No mock data for ${path}.`, { status: err.status, path });
      throw new ApiError("Could not read the mock data.", { path });
    }
  }
  const init = { method, headers: {} };
  if (json !== undefined) { init.headers["content-type"] = "application/json"; init.body = JSON.stringify(json); }
  if (form) init.body = form;
  let response;
  try {
    response = await fetch(API_BASE + target, init);
  } catch {
    throw new ApiError("The local service did not respond.", { path });
  }
  return readJson(response, path);
}

export const api = {
  get: (path, params) => send("GET", path, { params }),
  post: (path, body) => send("POST", path, { json: body }),
  put: (path, body) => send("PUT", path, { json: body }),
  /** multipart upload, e.g. POST /api/ingest/log with field "file" */
  upload: (path, file, field = "file") => {
    const form = new FormData();
    form.append(field, file);
    return send("POST", path, { form });
  },
  /** URL for the live stream, or null in mock mode. */
  streamUrl: () => (MOCK ? null : `${API_BASE}/api/stream`),
  mock: MOCK,
};

export default api;

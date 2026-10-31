// Live updates. SSE from /api/stream patches the store. While the stream is down the page polls
// /api/stats/summary every 3 s and shows last good data (SOT 6.8, design p9 banner).
import { api, MOCK } from "./api.js";
import { store } from "./store.js";

const POLL_MS = 3000;
const TYPES = ["event.new", "finding.new", "alert.new", "score.update", "remediation.update", "scenario.progress", "reset"];

let state = "connecting";          // "connecting" | "live" | "reconnecting" | "mock"
let source = null;
let pollTimer = null;
let refreshTimer = null;
let retryTimer = null;
let retryMs = 1000;
const stateListeners = new Set();
const handlers = new Map();        // type -> Set<fn>

function setState(next) {
  if (state === next) return;
  state = next;
  stateListeners.forEach((fn) => fn(state));
}

function emit(type, data) { handlers.get(type)?.forEach((fn) => fn(data)); }

function startPolling() {
  if (pollTimer) return;
  store.refresh("summary");
  pollTimer = setInterval(() => store.refresh("summary"), POLL_MS);
}
function stopPolling() { clearInterval(pollTimer); pollTimer = null; }

/** Many events arrive in a burst while a scenario plays: refresh the summary once a second at most. */
function refreshSoon() {
  if (refreshTimer) return;
  refreshTimer = setTimeout(() => { refreshTimer = null; store.refresh("summary"); }, 1000);
}

function apply(type, data) {
  switch (type) {
    case "alert.new":
      store.patch("alerts", (old) => old && { ...old, items: [data, ...(old.items ?? [])], total: (old.total ?? 0) + 1 });
      refreshSoon();
      break;
    case "score.update":
      store.patch("summary", (old) => old && { ...old, risk: data.risk });
      break;
    case "scenario.progress":
      store.patch("capture", (old) => old && { ...old, scenario: { name: data.name, played: data.played, total: data.total } });
      break;
    case "reset":
      store.reset();
      store.refresh("summary");
      store.refresh("health");
      break;
    case "event.new":
    case "finding.new":
      refreshSoon();
      break;
    default:
  }
  emit(type, data);
}

function open() {
  clearTimeout(retryTimer);
  source = new EventSource(api.streamUrl());
  source.onopen = () => {
    retryMs = 1000;
    stopPolling();
    setState("live");
    store.refresh("summary");
  };
  source.onerror = () => {
    setState("reconnecting");
    startPolling();
    // The browser retries by itself unless the connection was closed for good; then retry with back-off.
    if (source.readyState === EventSource.CLOSED) {
      source.close();
      retryTimer = setTimeout(open, retryMs);
      retryMs = Math.min(retryMs * 2, 15000);
    }
  };
  for (const type of TYPES) {
    source.addEventListener(type, (event) => {
      let data = {};
      try { data = JSON.parse(event.data); } catch { return; }
      apply(type, data);
    });
  }
}

export const live = {
  get state() { return state; },
  onState(fn) { stateListeners.add(fn); return () => stateListeners.delete(fn); },
  /** on("alert.new", fn). Returns an unsubscribe function. */
  on(type, fn) {
    if (!handlers.has(type)) handlers.set(type, new Set());
    handlers.get(type).add(fn);
    return () => handlers.get(type)?.delete(fn);
  },
  start() {
    if (MOCK) { setState("mock"); return; }       // no stream in mock mode, so nothing to poll for
    if (typeof EventSource === "undefined") { setState("reconnecting"); startPolling(); return; }
    startPolling();                                // data on screen while the stream connects
    open();
  },
  stop() { source?.close(); stopPolling(); clearTimeout(retryTimer); clearTimeout(refreshTimer); },
  /** For tests and the hosted preview: feed an event as if it came from the stream. */
  simulate(type, data) { apply(type, data); },
};

export default live;

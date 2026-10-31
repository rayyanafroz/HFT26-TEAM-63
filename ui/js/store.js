// Shared data for all screens. Topics map to API reads (SOT 6.7).
// Live updates (SSE patching and the 3 s polling fallback) live in live.js.
import { api } from "./api.js";

export const TOPICS = {
  health: "/api/health",
  summary: "/api/stats/summary",
  alerts: "/api/alerts",
  tools: "/api/tools",
  agents: "/api/agents",
  providers: "/api/providers",
  capture: "/api/capture/status",
  graph: "/api/graph",
  timeseries: "/api/stats/timeseries",
  findings: "/api/findings",
  compliance: "/api/compliance",
  explain: "/api/score/explain",
  evidence: "/api/evidence",
  visibility: "/api/visibility",
  sources: "/api/sources",          // not in SOT 6.7 yet: Home monitoring list (UD-01)
};

const state = new Map();       // topic -> { status: "idle"|"loading"|"ready"|"error", data, error, updatedAt }
const listeners = new Map();   // topic -> Set<fn>
const inflight = new Map();    // topic -> Promise

function entry(topic) {
  if (!state.has(topic)) state.set(topic, { status: "idle", data: null, error: null, updatedAt: null });
  return state.get(topic);
}

function emit(topic) {
  for (const fn of listeners.get(topic) ?? []) fn(entry(topic));
}

export const store = {
  /** Current data, or null before the first load. */
  get(topic) { return entry(topic).data; },
  /** Full entry, so a screen can tell loading from empty from error. */
  state(topic) { return entry(topic); },

  /** Calls fn(entry) on every change. Returns an unsubscribe function. Call it in unmount(). */
  subscribe(topic, fn) {
    if (!listeners.has(topic)) listeners.set(topic, new Set());
    listeners.get(topic).add(fn);
    return () => listeners.get(topic)?.delete(fn);
  },

  /** Re-read a topic from the API. Last good data stays in place if the call fails. */
  refresh(topic, params) {
    const path = TOPICS[topic];
    if (!path) return Promise.reject(new Error(`Unknown topic: ${topic}`));
    if (inflight.has(topic)) return inflight.get(topic);
    const e = entry(topic);
    e.status = e.data ? e.status : "loading";
    emit(topic);
    const run = api.get(path, params)
      .then((data) => { Object.assign(e, { status: "ready", data, error: null, updatedAt: Date.now() }); })
      .catch((error) => { Object.assign(e, { status: "error", error }); })
      .finally(() => { inflight.delete(topic); emit(topic); });
    inflight.set(topic, run);
    return run;
  },

  /** Replace or patch topic data from a live event. fn(oldData) -> newData */
  patch(topic, fn) {
    const e = entry(topic);
    const next = fn(e.data);
    if (next == null) return;            // nothing to patch yet: the screen will load the topic itself
    Object.assign(e, { status: "ready", data: next, error: null, updatedAt: Date.now() });
    emit(topic);
  },

  /** The "reset" stream event: clear every topic. */
  reset() {
    for (const topic of Object.keys(TOPICS)) {
      Object.assign(entry(topic), { status: "idle", data: null, error: null, updatedAt: null });
      emit(topic);
    }
  },
};

export default store;

// The link to the Shadow Lens desktop companion (the dashboard app), over Chrome Native Messaging.
//
// It is optional: the guard works the same without it. When the companion is installed
// (`python -m shadowlens.native_host install`), each guard event is also sent there, so the dashboard
// shows what was blocked across browsers. Only the history entry is sent: masks and hashes, no text.

export const HOST = "com.shadowlens.companion";
const IDLE_MS = 60_000;

let port = null;
let idleTimer = null;
let state = { connected: false, error: null, info: null, at: 0 };
const waiting = [];

function touch() {
  clearTimeout(idleTimer);
  // A connected native port keeps the service worker alive; let it go when nothing is happening.
  idleTimer = setTimeout(() => port?.disconnect(), IDLE_MS);
}

function connect() {
  if (port) return port;
  try {
    port = chrome.runtime.connectNative(HOST);
  } catch (e) {
    state = { connected: false, error: String(e?.message ?? e), info: null, at: Date.now() };
    return null;
  }
  port.onMessage.addListener((message) => {
    if (message?.type === "hello") {
      state = { connected: true, error: null, info: { version: message.version, dashboard: message.dashboard }, at: Date.now() };
      while (waiting.length) waiting.shift()(state);
    }
    touch();
  });
  port.onDisconnect.addListener(() => {
    const error = chrome.runtime.lastError?.message ?? null;
    state = { connected: false, error: error ?? (state.connected ? null : "the companion closed"), info: state.info, at: Date.now() };
    port = null;
    clearTimeout(idleTimer);
    while (waiting.length) waiting.shift()(state);
  });
  port.postMessage({ type: "hello", version: chrome.runtime.getManifest().version });
  touch();
  return port;
}

/** Send one history entry. Returns false when the companion is not reachable (that is not an error). */
export function sendEvent(entry) {
  const p = connect();
  if (!p) return false;
  try {
    p.postMessage({ type: "guard_event", event: entry });
    touch();
    return true;
  } catch {
    return false;
  }
}

/** Whether the companion answers, waiting up to two seconds for it to say hello. */
export function status() {
  if (state.connected && port) return Promise.resolve(state);
  return new Promise((resolve) => {
    waiting.push(resolve);
    if (!connect()) {
      waiting.splice(waiting.indexOf(resolve), 1);
      resolve(state);
      return;
    }
    setTimeout(() => {
      const i = waiting.indexOf(resolve);
      if (i >= 0) {
        waiting.splice(i, 1);
        resolve(state);
      }
    }, 2000);
  });
}

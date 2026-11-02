// Everything the extension keeps, and where.
//
//   chrome.storage.local    policy, the per-install salt, the history of what the guard did, counters.
//                           Never a raw value: history entries hold masks ("sk-p... (len 56)") and keyed hashes.
//   chrome.storage.session  the vault (placeholder -> real value) for each tab. Kept in memory only,
//                           readable only by the extension itself, gone when the tab or the browser closes.

import { emptyVault } from "../shared/placeholders.js";
import { mergePolicy } from "../shared/policy.js";

const HISTORY_MAX = 1000;
const local = chrome.storage.local;
const session = chrome.storage.session;

// Message handlers run concurrently; read-modify-write of one key goes through a queue.
const queues = new Map();
function serialized(key, work) {
  const run = (queues.get(key) ?? Promise.resolve()).then(work, work);
  queues.set(key, run.catch(() => {}));
  return run;
}

export async function getPolicy() {
  const { policy } = await local.get("policy");
  return mergePolicy(policy);
}

export function updatePolicy(change) {
  return serialized("policy", async () => {
    const current = await getPolicy();
    const next = mergePolicy(typeof change === "function" ? change(structuredClone(current)) : { ...current, ...change });
    await local.set({ policy: next });
    return next;
  });
}

/** 32 random bytes as hex, made once per install. Hashes in the history are keyed with it. */
export function getSalt() {
  return serialized("salt", async () => {
    const { salt } = await local.get("salt");
    if (typeof salt === "string" && /^[0-9a-f]{64}$/.test(salt)) return salt;
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const fresh = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    await local.set({ salt: fresh });
    return fresh;
  });
}

function dayKey(time) {
  const d = new Date(time);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** Keep only what is safe to keep: rule ids, masks, hashes, the site and what happened. */
export function historyEntry(event) {
  const at = Number.isFinite(event.at) ? event.at : Date.now();
  return {
    id: event.id ?? `${at.toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    at,
    site: String(event.site ?? "unknown").slice(0, 40),
    action: String(event.action ?? "unknown").slice(0, 20),
    kind: String(event.kind ?? "submit").slice(0, 20),
    severity: String(event.severity ?? "none").slice(0, 10),
    reason: typeof event.reason === "string" ? event.reason.slice(0, 300) : undefined,
    findings: (event.findings ?? []).slice(0, 50).map((f) => ({
      rule_id: String(f.rule_id).slice(0, 40),
      hash12: /^[0-9a-f]{12}$/.test(f.hash12) ? f.hash12 : undefined,
      masked_preview: String(f.masked_preview ?? "").slice(0, 80),
      severity: String(f.severity ?? "").slice(0, 10),
    })),
  };
}

export function addHistory(event) {
  return serialized("history", async () => {
    const entry = historyEntry(event);
    const { history = [], stats = { total: {}, days: {} } } = await local.get(["history", "stats"]);
    history.unshift(entry);
    history.length = Math.min(history.length, HISTORY_MAX);
    stats.total[entry.action] = (stats.total[entry.action] ?? 0) + 1;
    const day = (stats.days[dayKey(entry.at)] ??= {});
    day[entry.action] = (day[entry.action] ?? 0) + 1;
    // Keep 90 days of daily counts.
    for (const key of Object.keys(stats.days).sort().slice(0, -90)) delete stats.days[key];
    await local.set({ history, stats });
    return entry;
  });
}

export async function getHistory(limit = HISTORY_MAX) {
  const { history = [] } = await local.get("history");
  return history.slice(0, limit);
}

export async function getStats() {
  const { stats = { total: {}, days: {} } } = await local.get("stats");
  return { total: stats.total, today: stats.days[dayKey(Date.now())] ?? {}, days: stats.days };
}

export function clearHistory() {
  return serialized("history", () => local.set({ history: [], stats: { total: {}, days: {} } }));
}

const vaultKey = (tabId) => `vault:${tabId}`;

export async function getVault(tabId) {
  const key = vaultKey(tabId);
  const { [key]: vault } = await session.get(key);
  return vault ?? emptyVault();
}

/** Change a tab's vault under the queue, so two redactions in one tab never lose a placeholder. */
export function withVault(tabId, work) {
  return serialized(vaultKey(tabId), async () => {
    const vault = await getVault(tabId);
    const result = await work(vault);
    await session.set({ [vaultKey(tabId)]: vault });
    return result;
  });
}

export function dropVault(tabId) {
  return serialized(vaultKey(tabId), () => session.remove(vaultKey(tabId)));
}

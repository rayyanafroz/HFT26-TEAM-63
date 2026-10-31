// Helpers shared by screens.
import { el } from "../ui.js";

/** Subscribe to several store topics with one render function. Returns one unsubscribe function. */
export function watch(store, topics, render) {
  const offs = topics.map((t) => store.subscribe(t, render));
  return () => offs.forEach((off) => off());
}

/** Load topics the screen needs. Topics already loaded are refreshed quietly in the background. */
export function load(store, topics) {
  topics.forEach((t) => store.refresh(t));
}

/** Newest first. */
export function byNewest(items = []) {
  return [...items].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

/** Name lookup from a { items } list, e.g. tools by tool_id. Falls back to the id. */
export function namer(list, key) {
  const map = new Map((list?.items ?? []).map((x) => [x[key], x.display_name]));
  return (id) => map.get(id) ?? id ?? "–";
}

/** Small inline error for one card, with Retry. */
export function cardError(message, onRetry) {
  return el("div", { class: "card-error", role: "alert" },
    el("span", {}, message),
    el("button", { class: "linkbtn", type: "button", onClick: onRetry }, "Retry"));
}

/** What a source row (GET /api/sources) is counting: files for transcripts, requests for the tap, visits for browsers. */
export const SOURCE_UNIT = { transcript: "lines", live_log: "lines", proxy: "requests", browser: "visits" };

/** One short line for a source that is on, e.g. "3 files · 1,204 lines". */
export function sourceDetail(s, fmtNumber) {
  const n = `${fmtNumber(s.lines_ingested ?? 0)} ${SOURCE_UNIT[s.kind] ?? "lines"}`;
  return s.kind === "transcript" || s.kind === "live_log" ? `${fmtNumber(s.files_watched ?? 0)} files · ${n}` : n;
}

export const alertHref =(id) => `#/alerts?alert=${encodeURIComponent(id)}`;

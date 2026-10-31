// Small DOM and formatting helpers.
// API strings are untrusted (SOT 6.10): everything goes in through textContent or text nodes,
// never innerHTML.

const SVG_NS = "http://www.w3.org/2000/svg";

function applyAttrs(node, attrs) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.setAttribute("class", value);
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === "text") node.textContent = String(value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/** el("div", {class: "card"}, "text", otherNode) */
export function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  applyAttrs(node, attrs);
  append(node, children);
  return node;
}

/** svg("svg", {viewBox: "0 0 64 64"}, svg("path", {...})) */
export function svg(tag, attrs, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "text") node.textContent = String(value);       // untrusted strings go in as text, never markup
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

/** Remove all children of a node. */
export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

const pad = (n) => String(n).padStart(2, "0");

/** ISO timestamp -> "09:41:12" (24 h, local time). Returns "–" for missing or invalid input. */
export function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "–";
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** 1284 -> "1,284" */
export function fmtNumber(n) {
  return typeof n === "number" ? n.toLocaleString("en-US") : "–";
}

/** 2150 -> "2.1 KB". null -> "–" (bytes_out is null when unknown). */
export function fmtBytes(n) {
  if (typeof n !== "number") return "–";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** Percent of a part within a whole, rounded. 0 when the whole is 0. */
export function pct(part, whole) {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

/** Band names from the API (SOT 6.6) -> label shown in the design. "high" shows as "Elevated" (design p7, p13). */
const BAND_LABELS = { low: "Low", moderate: "Moderate", high: "Elevated", critical: "Critical" };
export function bandLabel(band) {
  return BAND_LABELS[band] ?? "–";
}

/* Semantic tones (colour pass): red = high or critical, amber = medium or needs attention, green = low, safe or resolved. */
const BAND_TONE = { low: "tone-green", moderate: "tone-amber", high: "tone-red", critical: "tone-red" };
const SEV_TONE = { critical: "tone-red", high: "tone-red", medium: "tone-amber", low: "tone-green" };
export const bandTone = (band) => BAND_TONE[band] ?? "";
export const sevTone = (sev) => SEV_TONE[sev] ?? "";
/** Compliance score is 100 minus org risk, so it uses the same cut points the other way round. */
export const scoreTone = (score) => (score >= 76 ? "tone-green" : score >= 51 ? "tone-amber" : "tone-red");

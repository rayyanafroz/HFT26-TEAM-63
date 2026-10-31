// Shared UI primitives. Each function returns a DOM node. Styles live in app.css.
// Design reference: Frontend Design PDF p. 3 (components), Brand Guidelines p. 15, 25, 26.
import { el, svg, pct } from "../ui.js";

/* ---------- Logo (brand p26, "the mark as code") ---------- */
export function logoMark({ size = 32, night = false } = {}) {
  const small = size < 24;                       // small cut under 24 px
  const edge = night ? "#3FC1B8" : "#0B7A75";
  const node = svg("svg", { viewBox: "0 0 64 64", width: size, height: size, role: "img", "aria-label": "ShadowLens" },
    svg("path", { d: small ? "M32 7A25 25 0 0 0 32 57Z" : "M32 6A26 26 0 0 0 32 58Z", fill: "currentColor" }),
    svg("circle", { cx: 32, cy: 32, r: small ? 25 : 26, fill: "none", stroke: "currentColor", "stroke-width": small ? 7 : 5 }),
    small
      ? svg("rect", { x: 28, y: 0, width: 8, height: 64, fill: edge })
      : svg("rect", { x: 29.5, y: 1, width: 5, height: 62, fill: edge }));
  return node;
}

export function logo({ night = false, size = 28 } = {}) {
  const mark = logoMark({ size, night });
  mark.setAttribute("aria-hidden", "true");
  mark.removeAttribute("role");
  mark.removeAttribute("aria-label");
  return el("span", { class: `logo${night ? " logo--night" : ""}` },
    mark, el("span", { class: "logo__word" }, "ShadowLens"));
}

/* ---------- Buttons ---------- */
/** variant: "primary" | "secondary" | "small" */
export function button({ label, variant = "primary", disabled = false, block = false, onClick, type = "button", ariaLabel } = {}) {
  const cls = ["btn", variant === "secondary" && "btn--secondary", variant === "small" && "btn--small", block && "btn--block"]
    .filter(Boolean).join(" ");
  return el("button", { class: cls, type, disabled, "aria-label": ariaLabel, onClick }, label);
}

/* ---------- Toggle ---------- */
export function toggle({ checked = false, disabled = false, label = "", onChange, name } = {}) {
  const input = el("input", { class: "toggle__input", type: "checkbox", role: "switch", name, disabled });
  input.checked = checked;
  if (onChange) input.addEventListener("change", () => onChange(input.checked));
  return el("label", { class: "toggle" }, input, el("span", { class: "toggle__track" }),
    label ? el("span", { class: "toggle__text" }, label) : null);
}

/* ---------- Filter chip and segmented tabs ---------- */
export function chip({ label, pressed = false, onClick } = {}) {
  const node = el("button", { class: "chip", type: "button", "aria-pressed": String(pressed) }, label);
  node.addEventListener("click", () => {
    if (onClick) onClick(node);
  });
  return node;
}

/** items: [{id, label}]. Single selection. onSelect(id). */
export function segmented({ items, selected, onSelect } = {}) {
  const wrap = el("div", { class: "segmented", role: "group" });
  const buttons = items.map((item) => {
    const b = chip({ label: item.label, pressed: item.id === selected, onClick: () => {
      buttons.forEach((x, i) => x.setAttribute("aria-pressed", String(items[i].id === item.id)));
      if (onSelect) onSelect(item.id);
    } });
    return b;
  });
  wrap.append(...buttons);
  return wrap;
}

/* ---------- Inputs ---------- */
export function searchInput({ placeholder = "Search", value = "", onInput } = {}) {
  const input = el("input", { class: "input", type: "search", placeholder, value, "aria-label": placeholder });
  if (onInput) input.addEventListener("input", () => onInput(input.value));
  return input;
}

/** Select-style trigger ("Tool ▾"). Option lists are not drawn in the design (UD-19). */
export function selectButton({ label, onClick } = {}) {
  return el("button", { class: "input", type: "button", "aria-haspopup": "listbox", onClick },
    el("span", {}, label), el("span", { "aria-hidden": "true", style: "font-size:10px;margin-left:8px" }, "▾"));
}

/* ---------- Severity mark: four bars plus label weight ---------- */
const SEV_BARS = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_LABELS = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export function sevMark(severity) {
  const level = SEV_BARS[severity] !== undefined ? severity : "info";
  const bars = el("span", { class: "sev__bars", "aria-hidden": "true" },
    ...[0, 1, 2, 3].map((i) => el("i", { class: i < SEV_BARS[level] ? "on" : "" })));
  return el("span", { class: `sev sev--${level}` }, bars, el("span", { class: "sev__label" }, SEV_LABELS[level]));
}

/* ---------- State cell ---------- */
/** kind: "absent" | "granted" | "used" | "unseen" (used but not granted). risky adds the "risky" tag. */
const CELL_LABELS = { absent: "not present", granted: "granted", used: "used", unseen: "used, not granted" };
export function stateCell(kind, { label, risky = false, showLabel = true } = {}) {
  const text = label ?? CELL_LABELS[kind] ?? kind;
  if (kind === "absent") {
    return el("span", { class: "cell cell--absent" }, el("span", { "aria-hidden": "true" }, "–"), showLabel ? el("span", {}, text) : el("span", { class: "visually-hidden" }, text));
  }
  return el("span", { class: `cell cell--${kind}` },
    el("span", { class: "cell__mark", "aria-hidden": "true" }),
    showLabel ? el("span", {}, text) : el("span", { class: "visually-hidden" }, text),
    risky ? el("span", { class: "tag tag--risky" }, "risky") : null);
}

export function tag(text) {
  return el("span", { class: "tag" }, text);
}

/* ---------- Coverage band ---------- */
/** Always shows both the bar and the numbers. */
export function coverageBand({ full = 0, metadataOnly = 0, night = false } = {}) {
  const total = full + metadataOnly;
  const fullPct = pct(full, total);
  const metaPct = total > 0 ? 100 - fullPct : 0;
  const seen = el("div", { class: "coverage__seen", style: `width:${fullPct}%` });
  const unseen = el("div", { class: "coverage__unseen" });
  return el("div", { class: `coverage${night ? " coverage--night" : ""}`, role: "img",
    "aria-label": `Full visibility ${fullPct} percent, metadata only ${metaPct} percent` },
    el("div", { class: "coverage__bar" }, seen, unseen),
    el("div", { class: "coverage__nums" },
      el("span", {}, `full visibility ${fullPct}%`),
      el("span", {}, `metadata only ${metaPct}%`)));
}

/* ---------- Redaction ---------- */
export function redaction({ width } = {}) {
  const node = el("span", { class: "redact", role: "img", "aria-label": "redacted" });
  if (width) node.style.width = typeof width === "number" ? `${width}px` : width;
  return node;
}

/* ---------- Cards and metric tile ---------- */
/** variant: "white" | "tint" | "night" */
export function card({ variant = "white", label, className = "" } = {}, ...children) {
  const cls = ["card", variant === "tint" && "card--tint", variant === "night" && "card--night", className].filter(Boolean).join(" ");
  return el("section", { class: cls }, label ? el("h2", { class: "label card__label" }, label) : null, ...children);
}

export function metricTile({ label, value, sub, variant = "white" } = {}) {
  const cls = ["card", "metric", variant === "tint" && "card--tint", variant === "night" && "card--night"].filter(Boolean).join(" ");
  return el("div", { class: cls },
    el("div", { class: "label" }, label),
    el("div", { class: "metric__value" }, value),
    sub ? el("div", { class: "metric__sub" }, sub) : null);
}

/* ---------- Banner, error, loading, empty ---------- */
export function banner(text, { right } = {}) {
  return el("div", { class: "banner", role: "status", style: right ? "display:flex;justify-content:space-between;gap:16px" : "" },
    el("span", {}, text), right ? el("span", { class: "mono" }, right) : null);
}

/** Error with a Retry action. Text states what failed (design p9: "Could not load alerts. The local service did not respond."). */
export function errorBlock({ message, onRetry } = {}) {
  return el("div", { class: "state-block", role: "alert" },
    el("div", { class: "error-box" }, message),
    onRetry ? button({ label: "Retry", onClick: onRetry }) : null);
}

export function loadingText(text = "Loading…") {
  return el("div", { class: "state-block" },
    el("div", { class: "loading-text", role: "status" }, text));
}

/** Empty block. Text only: hatch never marks an empty state (brand p25). */
export function emptyBlock({ message, actions = [] } = {}) {
  return el("div", { class: "state-block" },
    el("div", { class: "h3" }, message), actions.length ? el("div", { style: "display:flex;gap:16px" }, ...actions) : null);
}

/* ---------- Toast ---------- */
/** variant: "alert" | "info" | "error". error carries a Retry button. */
export function toast({ label, title, text, linkLabel, onLink, onClose, onRetry, variant = "alert" } = {}) {
  const node = el("div", { class: `toast${variant === "error" ? " toast--error" : ""}`, role: variant === "error" ? "alert" : "status" },
    el("div", { class: "toast__label" }, label),
    el("div", { class: "toast__title" }, title),
    text ? el("div", { class: "toast__text" }, text) : null,
    linkLabel ? el("a", { class: "toast__link", href: "#", onClick: (e) => { e.preventDefault(); if (onLink) onLink(); } }, linkLabel) : null,
    variant === "error" && onRetry ? el("div", { style: "margin-top:12px" }, button({ label: "Retry", variant: "small", onClick: onRetry })) : null,
    onClose ? el("button", { class: "toast__close", type: "button", "aria-label": "Dismiss", onClick: onClose }, "×") : null);
  return node;
}

/* ---------- Code block ---------- */
export function codeBlock(text) {
  return el("pre", { class: "code" }, text);
}

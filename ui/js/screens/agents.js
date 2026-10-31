// Agents (Frontend Design PDF p13). Capability matrix from GET /api/agents.
// The per-agent timeline (p14) is P2 and is not built.
import { el, fmtTime, bandLabel, bandTone } from "../ui.js";
import { watch, load } from "./util.js";
import { ruleName } from "../rules.js";

const CAPS = [["shell", "Shell"], ["fs_read", "File read"], ["fs_write", "File write"], ["network", "Network"], ["mcp", "MCP"], ["sensitive_file", "Sensitive file"]];
const CAP_NAME = Object.fromEntries(CAPS);

export function cellKind(c) {
  if (!c || (!c.granted && !c.used)) return "absent";
  if (c.used && !c.granted) return "unseen";
  return c.used ? "used" : "granted";
}
const KIND_TEXT = { absent: "not present", granted: "granted, not used", used: "used", unseen: "used, not granted" };

export function mount(container, ctx) {
  const { store, primitives: P } = ctx;
  let sel = null;   // { tool_id, cap }

  const legend = el("div", { class: "legend" },
    el("span", { class: "label" }, "Cell states"),
    el("span", {}, "– not present"),
    el("span", {}, P.stateCell("granted", { showLabel: false }), " granted"),
    el("span", {}, P.stateCell("used", { showLabel: false }), " used"),
    el("span", {}, P.stateCell("unseen", { showLabel: false }), " used but not granted"),
    el("span", {}, el("span", { class: "tag tag--risky" }, "risky"), " risky use"));
  const tableBox = el("div", { class: "card agents-table" });
  const detail = el("div", {});
  container.append(
    el("header", { class: "screen-head" }, el("h1", { class: "h2" }, "Agents"), el("p", { class: "small" }, "What each agent is allowed to do, and what it did.")),
    legend, tableBox, detail);

  function pickDefault(items) {
    for (const a of items) for (const [k] of CAPS) if (a.capabilities[k]?.risky) return { tool_id: a.tool_id, cap: k };
    return null;
  }

  function render() {
    const entry = store.state("agents");
    if (!entry.data && entry.status === "error") {
      tableBox.replaceChildren(el("div", { class: "table-state" }, P.errorBlock({ message: `Could not load agents. ${entry.error.message}`, onRetry: () => store.refresh("agents") })));
      detail.replaceChildren(); return;
    }
    if (!entry.data) { tableBox.replaceChildren(el("div", { class: "table-state" }, P.loadingText("Loading agents…"))); return; }
    const items = [...entry.data.items].sort((a, b) => b.risk - a.risk);
    if (!items.length) {
      tableBox.replaceChildren(el("div", { class: "table-state" }, P.emptyBlock({ message: "No agents seen yet. Agents appear when a tool declares or runs a capability." })));
      detail.replaceChildren(); return;
    }
    if (!sel || !items.some((a) => a.tool_id === sel.tool_id)) sel = pickDefault(items);

    const head = el("thead", {}, el("tr", {},
      el("th", { scope: "col" }, "Agent"), el("th", { scope: "col" }, "Risk"), el("th", { scope: "col" }, "Band"),
      ...CAPS.map(([, l]) => el("th", { scope: "col" }, l))));
    const body = el("tbody", {}, ...items.map((a) => el("tr", { class: sel?.tool_id === a.tool_id ? "is-selected" : "" },
      el("th", { scope: "row", class: "agents__name" }, el("strong", {}, a.display_name), el("span", { class: "mono" }, a.process)),
      el("td", { class: `agents__risk ${bandTone(a.risk_band)}` }, String(a.risk)),
      el("td", { class: bandTone(a.risk_band) }, bandLabel(a.risk_band)),
      ...CAPS.map(([k, l]) => {
        const c = a.capabilities[k];
        const kind = cellKind(c);
        const label = `${a.display_name}, ${l}: ${KIND_TEXT[kind]}${c?.risky ? ", risky" : ""}`;
        if (kind === "absent") return el("td", { class: "agents__absent" }, el("span", { "aria-label": label }, "–"));
        const on = sel?.tool_id === a.tool_id && sel?.cap === k;
        return el("td", {}, el("button", { class: `cellbtn${on ? " is-on" : ""}`, type: "button", "aria-label": label, "aria-pressed": String(on),
          onClick: () => { sel = { tool_id: a.tool_id, cap: k }; render(); } }, P.stateCell(kind, { showLabel: false, risky: c.risky })));
      }))));
    tableBox.replaceChildren(el("div", { class: "table-scroll" }, el("table", { class: "table agents" }, head, body)));

    const a = sel && items.find((x) => x.tool_id === sel.tool_id);
    if (!a) { detail.replaceChildren(el("p", { class: "small agents__hint" }, "Select a cell to see what the agent did.")); return; }
    const c = a.capabilities[sel.cap];
    const kind = cellKind(c);
    const acts = (a.activity ?? []).filter((x) => x.capability === sel.cap);
    const last = acts[acts.length - 1];
    const capText = { granted: "granted, not used", used: "used", unseen: "not granted" }[kind];
    detail.replaceChildren(el("section", { class: "cell-detail", "aria-live": "polite" },
      el("h2", { class: "label" }, `Cell detail · ${a.display_name} · ${CAP_NAME[sel.cap]}`),
      el("dl", { class: "pkv" },
        el("dt", {}, "Capability"), el("dd", {}, `${CAP_NAME[sel.cap]}, ${capText}${c.risky ? ", risky" : ""}`),
        last?.rule_id ? el("dt", {}, "Rule") : null, last?.rule_id ? el("dd", { class: "mono" }, `${last.rule_id} · ${ruleName(last.rule_id)}`) : null,
        last?.name ? el("dt", {}, "Tool name") : null, last?.name ? el("dd", { class: "mono" }, last.name) : null,
        el("dt", {}, "Last argument"), el("dd", { class: "mono" }, last?.argument ? withRedaction(last.argument) : "none recorded"),
        last ? el("dt", {}, "Last seen") : null, last ? el("dd", { class: "mono" }, fmtTime(last.ts)) : null)));
  }

  function withRedaction(text) {
    return el("span", {}, ...String(text).split(/(\[REDACTED\])/).map((p) => (p === "[REDACTED]" ? P.redaction({ width: 90 }) : p)));
  }

  const off = watch(store, ["agents"], render);
  render();
  load(store, ["agents"]);
  return off;
}

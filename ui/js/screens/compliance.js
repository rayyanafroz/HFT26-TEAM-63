// Compliance (Frontend Design PDF p19 controls, p20 why this score, p21 evidence). ?tab=controls|why|evidence
import { el, fmtNumber, fmtTime, bandLabel, bandTone, scoreTone } from "../ui.js";
import { watch, load, namer } from "./util.js";
import { ruleName } from "../rules.js";

const TABS = [{ id: "controls", label: "Controls" }, { id: "why", label: "Why this score" }, { id: "evidence", label: "Evidence" }];
const FRAMEWORK = { owasp_llm: "OWASP LLM Top 10", internal: "Internal policy" };
const EVAL_CMD = "python -m shadowlens.eval.run";

export function mount(container, ctx) {
  const { store, primitives: P } = ctx;
  let tab = TABS.some((t) => t.id === ctx.params.tab) ? ctx.params.tab : "controls";
  let toolId = null;

  const tabs = P.segmented({ items: TABS, selected: tab, onSelect: (id) => { location.hash = `#/compliance?tab=${id}`; } });
  tabs.classList.add("cmp-tabs");
  const top = el("div", { class: "cmp-top" });
  const body = el("div", {});
  container.append(
    el("header", { class: "screen-head" }, el("h1", { class: "h2" }, "Compliance"), el("p", { class: "small" }, "Explain the score and map findings to controls.")),
    top, tabs, body);

  const stateOf = (topic, what) => {
    const e = store.state(topic);
    // The backend does not serve this endpoint yet: say so plainly, with no Retry (retrying cannot help).
    if (!e.data && e.status === "error" && (e.error.status === 404 || e.error.status === 405)) return P.emptyBlock({ message: `The local service does not provide ${what} yet.` });
    if (!e.data && e.status === "error") return P.errorBlock({ message: `Could not load ${what}. ${e.error.message}`, onRetry: () => store.refresh(topic, topic === "explain" && toolId ? { tool_id: toolId } : undefined) });
    if (!e.data) return P.loadingText(`Loading ${what}…`);
    return null;
  };

  function renderTop() {
    const c = store.get("compliance");
    const risk = c ? { org_risk: c.org_risk, band: c.band, compliance_score: c.compliance_score } : store.get("summary")?.risk;
    top.replaceChildren(
      el("section", { class: "card cmp-score" }, el("h2", { class: "label" }, "Compliance score"), el("div", { class: `cmp-score__num ${risk ? scoreTone(risk.compliance_score) : ""}` }, risk ? String(risk.compliance_score) : "–")),
      el("section", { class: "card cmp-risk" }, el("h2", { class: "label" }, "AI risk"),
        el("div", { class: "cmp-risk__line" }, el("span", { class: `cmp-risk__num ${risk ? bandTone(risk.band) : ""}` }, risk ? String(risk.org_risk) : "–"), risk ? el("span", { class: `cmp-risk__band ${bandTone(risk.band)}` }, bandLabel(risk.band)) : null)),
      el("section", { class: "card cmp-note" }, el("p", {},
        el("strong", {}, c?.disclaimer ?? "This is an interpretation of risk, not an audit."),
        " Controls are mapped from findings. A gap means a finding maps to the control.")));
  }

  /* ---------- p19 controls ---------- */
  function controlsView() {
    const s = stateOf("compliance", "the controls");
    if (s) return el("section", { class: "card ov-state" }, s);
    const rows = store.get("compliance").controls;
    if (!rows.length) return el("section", { class: "card ov-state" }, P.emptyBlock({ message: "No controls are configured." }));
    return el("section", { class: "card cmp-table" }, el("div", { class: "table-scroll" }, el("table", { class: "table cmp" },
      el("thead", {}, el("tr", {}, ...["Framework", "Control", "Title", "Status", "Findings", ""].map((h) => el("th", { scope: "col" }, h || el("span", { class: "visually-hidden" }, "Links"))))),
      el("tbody", {}, ...rows.map((r) => el("tr", {},
        el("td", {}, FRAMEWORK[r.framework] ?? r.framework),
        el("td", { class: "mono" }, r.id),
        el("th", { scope: "row" }, r.title),
        el("td", { class: r.status === "gap" ? "cell-tone-amber" : "cell-tone-green" }, P.stateCell(r.status === "gap" ? "unseen" : "granted", { label: r.status })),
        el("td", { class: "mono" }, fmtNumber(r.finding_count)),
        el("td", {}, r.finding_count ? el("a", { class: "monolink", href: `#/alerts?control=${encodeURIComponent(r.id)}` }, "View alerts") : el("span", { class: "small" }, "no alerts"))))))));
  }

  /* ---------- p20 why this score ---------- */
  const toolText = el("span", {}, "Tool");
  const toolBtn = el("button", { class: "input filters__select filters__select--wide cmp-toolsel", type: "button", "aria-haspopup": "listbox" }, toolText, el("span", { class: "caret", "aria-hidden": "true" }, "▾"));
  const toolMenu = el("ul", { class: "menu menu--light", role: "listbox", hidden: true });
  toolBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (!toolMenu.hidden) { toolMenu.hidden = true; return; }
    const tools = [...(store.get("tools")?.items ?? [])].sort((a, b) => b.risk - a.risk);
    toolMenu.replaceChildren(...tools.map((t) => el("li", { role: "option", tabindex: "0",
      onClick: () => { toolId = t.tool_id; toolMenu.hidden = true; store.refresh("explain", { tool_id: toolId }); render(); },
      onKeydown: (ev) => { if (ev.key === "Enter") ev.target.click(); } }, `${t.display_name} · ${t.risk}`)));
    toolMenu.hidden = false; toolMenu.firstElementChild?.focus();
  });
  const onDoc = () => { toolMenu.hidden = true; };
  document.addEventListener("click", onDoc);

  function whyView() {
    const x = store.get("explain");
    const toolName = namer(store.get("tools"), "tool_id");
    if (x) toolText.textContent = toolName(x.tool_id);
    const left = el("section", { class: "card cmp-why" },
      el("div", { class: "lab__head" }, el("h2", { class: "label" }, "Step by step · tool"), el("div", { style: "position:relative" }, toolBtn, toolMenu)));
    const right = el("section", { class: "card" }, el("h2", { class: "label card__label" }, "From findings to organisation risk"));
    const s = stateOf("explain", "the score explanation");
    if (s) { left.append(s); return el("div", { class: "cmp-whygrid" }, left, right); }
    const items = x.items ?? [];
    const f1 = (n) => Number(n).toFixed(1);
    left.append(
      items.length
        ? el("table", { class: "why" },
            el("thead", { class: "visually-hidden" }, el("tr", {}, el("th", {}, "Finding"), el("th", {}, "How the points are worked out"), el("th", {}, "Points"))),
            el("tbody", {}, ...items.map((i) => el("tr", {},
              el("th", { scope: "row" }, el("span", { class: "mono" }, i.rule_id), el("span", { class: "why__name" }, ruleName(i.rule_id))),
              el("td", { class: "why__calc" }, `${i.w_sev} × ${i.confidence} × ${i.m_exposure} × ${i.m_sanction} × ${i.count_factor}`),
              el("td", { class: "why__pts" }, f1(i.points))))),
            el("tfoot", {},
              el("tr", {}, el("th", { scope: "row", colspan: "2" }, `Sum S = ${items.map((i) => f1(i.points)).join(" + ")}`), el("td", { class: "why__pts" }, f1(x.S))),
              el("tr", {}, el("th", { scope: "row", colspan: "2" }, `Tool score = 100 × (1 − e^(−S/80))`), el("td", { class: "why__pts" }, String(x.score)))))
        : el("p", { class: "small" }, "This tool has no scored findings."),
      el("p", { class: "small why__key" }, "Points = severity weight × confidence × exposure × approval × repeat factor."));
    const o = x.org;
    right.append(
      el("ol", { class: "flow" },
        el("li", { class: "flow__step" }, `${items.length} finding${items.length === 1 ? "" : "s"} → `, el("strong", { class: "mono" }, f1(x.S)), " points"),
        el("li", { class: "flow__step" }, "Tool score ", el("strong", { class: "mono" }, String(x.score)), `, band ${bandLabel(scoreBand(x.score))}`),
        o ? el("li", { class: "flow__step flow__step--night" }, "Organisation risk ", el("strong", {}, String(o.org_risk)), " (AI Risk)") : null),
      o ? el("p", { class: "small flow__formula" }, `0.7 × highest tool score ${o.max_tool_score} + 0.3 × mean of top 3 ${f1(o.mean_top3)} = ${o.org_risk}. Compliance score = 100 − ${o.org_risk} = ${o.compliance_score}.`) : null,
      el("p", { class: "small" }, "Every number comes from a rule you can open."));
    return el("div", { class: "cmp-whygrid" }, left, right);
  }
  const scoreBand = (n) => (n >= 75 ? "critical" : n >= 50 ? "high" : n >= 25 ? "moderate" : "low");

  /* ---------- p21 evidence ---------- */
  function evidenceView() {
    const s = stateOf("evidence", "the evidence");
    if (s) return el("section", { class: "card ov-state" }, s);
    const ev = store.get("evidence");
    const ifNone = el("section", { class: "card cmp-ifnone" }, el("h2", { class: "label" }, "If unavailable"),
      el("p", { class: "cmp-ifnone__cmd" }, "Run ", el("code", { class: "mono" }, EVAL_CMD)));
    if (!ev.available || !ev.metrics?.length) return el("div", { class: "cap" }, el("section", { class: "card ov-state" }, P.emptyBlock({ message: "No evaluation results yet." })), ifNone);
    const cmp = (m) => {
      if (m.value === m.target) return "";
      const above = m.value >= m.target;
      return (m.pass ? above : !above) ? "≥" : "≤";
    };
    const dec = (m) => (String(m.value).split(".")[1] ?? "").length;
    const tgt = (m) => (dec(m) ? Number(m.target).toFixed(dec(m)) : String(m.target));
    const unit = (u) => (u ? (u.startsWith("of") || u === "found" || u === "ms" ? ` ${u}` : u) : "");
    return el("div", { class: "cap" },
      el("section", { class: "card cmp-table" }, el("div", { class: "table-scroll" }, el("table", { class: "table cmp" },
        el("thead", {}, el("tr", {}, ...["Metric", "Value", "Target", "Result", "Command"].map((h) => el("th", { scope: "col" }, h)))),
        el("tbody", {}, ...ev.metrics.map((m) => el("tr", {},
          el("th", { scope: "row" }, m.label),
          el("td", { class: "mono" }, `${m.value}${unit(m.unit)}`),
          el("td", { class: "mono" }, `${cmp(m) ? `${cmp(m)} ` : ""}${tgt(m)}${unit(m.unit)}`),
          el("td", { class: m.pass ? "cell-tone-green" : "cell-tone-red" }, P.stateCell(m.pass ? "used" : "unseen", { label: m.pass ? "pass" : "fail" })),
          el("td", { class: "mono-cell" }, m.command))))))),
      el("p", { class: "small" }, ev.generated_at ? `Results from ${fmtTime(ev.generated_at)}. Run ${EVAL_CMD} to refresh them.` : `Run ${EVAL_CMD} to refresh the results.`));
  }

  function render() {
    renderTop();
    body.replaceChildren(tab === "why" ? whyView() : tab === "evidence" ? evidenceView() : controlsView());
  }
  const off = watch(store, ["compliance", "explain", "evidence", "summary", "tools"], render);
  render();
  load(store, ["compliance", "evidence", "tools", "summary"]);
  store.refresh("explain");
  return {
    update(params) {
      const next = TABS.some((t) => t.id === params.tab) ? params.tab : "controls";
      if (next !== tab) { tab = next; tabs.querySelectorAll(".chip").forEach((c, i) => c.setAttribute("aria-pressed", String(TABS[i].id === tab))); render(); }
    },
    unmount() { off(); document.removeEventListener("click", onDoc); },
  };
}

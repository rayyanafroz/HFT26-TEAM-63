// Overview (Frontend Design PDF p7, states p9). The exposure graph (p8) arrives in Phase 8.
import { el, fmtNumber, fmtTime, bandLabel, bandTone } from "../ui.js";
import { watch, load, byNewest, namer, cardError, alertHref } from "./util.js";
import { exposureGraph } from "../components/graph.js";

const TOPICS = ["summary", "alerts", "tools", "providers", "timeseries", "graph"];
const SEVS = ["critical", "high", "medium", "low"];

export function mount(container, ctx) {
  const { store, live, primitives: P, runScenario } = ctx;
  const root = el("div", { class: "ov" });
  container.append(root);
  let selectedNode = null;

  /* ---------- top row ---------- */
  function riskCard(s) {
    const r = s.risk;
    const stat = (label, value) => el("div", { class: "ov-risk__stat" }, el("div", { class: "label" }, label), el("div", { class: "ov-risk__val" }, value));
    return el("section", { class: "card card--night ov-risk" },
      el("h2", { class: "label" }, "AI risk"),
      el("div", { class: "risk__line" }, el("span", { class: `risk__num ${bandTone(r.band)}` }, String(r.org_risk)), el("span", { class: `risk__band ${bandTone(r.band)}` }, bandLabel(r.band))),
      el("div", { class: "ov-risk__stats" },
        stat("Compliance score", String(r.compliance_score)),
        stat("Last event", fmtTime(s.last_event_at)),
        stat("Scenario", s.scenario ?? "none")));
  }

  function tile(label, value, sub, tint, tone = "") {
    return el("section", { class: `card ov-tile${tint ? " card--tint" : ""}` },
      el("h2", { class: "label" }, label),
      el("div", { class: `ov-tile__val ${tone}` }, value),
      sub ? el("div", { class: "ov-tile__sub" }, sub) : null);
  }

  /* ---------- middle row ---------- */
  function severityCard(s) {
    const counts = SEVS.map((k) => s.alerts_by_severity[k] ?? 0);
    const max = Math.max(1, ...counts);
    return el("section", { class: "card ov-sev" },
      el("h2", { class: "label card__label" }, "Alerts by severity"),
      el("ul", { class: "barlist barlist--sev" }, ...SEVS.map((k, i) => el("li", {},
        P.sevMark(k),
        el("span", { class: "barlist__track" }, el("span", { class: `barlist__fill barlist__fill--ink sevfill--${k}`, style: `width:${(counts[i] / max) * 100}%` })),
        el("span", { class: "barlist__num" }, String(counts[i]))))));
  }

  function providerCard(s) {
    const rows = [...(s.events_by_provider ?? [])].sort((a, b) => b.count - a.count).slice(0, 6);
    const max = Math.max(1, ...rows.map((r) => r.count));
    return el("section", { class: "card ov-prov" },
      el("h2", { class: "label card__label" }, "Events by provider"),
      rows.length
        ? el("ul", { class: "barlist" }, ...rows.map((r) => el("li", {},
            el("span", { class: "barlist__name" }, r.display_name),
            el("span", { class: "barlist__track barlist__track--tint" }, el("span", { class: "barlist__fill", style: `width:${(r.count / max) * 100}%` })),
            el("span", { class: "barlist__num" }, fmtNumber(r.count)))))
        : el("p", { class: "small" }, "No provider traffic yet."));
  }

  function timelineCard() {
    const entry = store.state("timeseries");
    let body;
    if (!entry.data && entry.status === "error") body = cardError(`Could not load the timeline. ${entry.error.message}`, () => store.refresh("timeseries"));
    else if (!entry.data) body = el("p", { class: "loading-text loading-text--small", role: "status" }, "Loading the timeline…");
    else {
      const buckets = entry.data.buckets ?? [];
      const max = Math.max(1, ...buckets.map((b) => b.events + b.alerts));
      const totalE = buckets.reduce((n, b) => n + b.events, 0);
      const totalA = buckets.reduce((n, b) => n + b.alerts, 0);
      body = buckets.length
        ? el("div", { class: "tl", role: "img", "aria-label": `${buckets.length} intervals of ${entry.data.bucket_s} s: ${totalE} events, ${totalA} alerts` },
            ...buckets.map((b) => el("div", { class: "tl__col", title: `${fmtTime(b.t)} · ${b.events} events · ${b.alerts} alerts` },
              b.alerts ? el("span", { class: "tl__alerts", style: `height:max(4px, ${(b.alerts / max) * 100}%)` }) : null,
              el("span", { class: "tl__events", style: `height:${(b.events / max) * 100}%` }))))
        : el("p", { class: "small" }, "No activity in this period.");
    }
    return el("section", { class: "card ov-tl" },
      el("div", { class: "ov-head" }, el("h2", { class: "label" }, "Timeline"), el("span", { class: "ov-legend" }, "teal = events · ink = alerts")),
      body);
  }

  /* ---------- live feed ---------- */
  function feedCard() {
    const entry = store.state("alerts");
    const toolName = namer(store.get("tools"), "tool_id");
    const provName = namer(store.get("providers"), "provider_id");
    let body;
    if (!entry.data && entry.status === "error") body = cardError(`Could not load alerts. ${entry.error.message}`, () => store.refresh("alerts"));
    else if (!entry.data) body = el("p", { class: "loading-text loading-text--small", role: "status" }, "Loading alerts…");
    else {
      const items = byNewest(entry.data.items).slice(0, 12);
      body = items.length
        ? el("ul", { class: "feed" }, ...items.map((a) => el("li", {},
            el("a", { class: "feed__row", href: alertHref(a.id) },
              P.sevMark(a.severity),
              el("span", { class: "feed__title" }, a.title),
              el("span", {}, toolName(a.tool_id)),
              el("span", {}, provName(a.provider_id)),
              el("span", { class: "feed__time" }, fmtTime(a.created_at))))))
        : el("p", { class: "small" }, "No alerts yet. New alerts appear here as they are raised.");
    }
    return el("section", { class: "card ov-feed" },
      el("div", { class: "ov-head" }, el("h2", { class: "label" }, "Live feed"), el("span", { class: "ov-legend" }, "newest first")),
      body);
  }

  /* ---------- exposure graph (p8) ---------- */
  function graphSection() {
    const entry = store.state("graph");
    const card = el("section", { class: "card xg-card" },
      el("div", { class: "ov-head" }, el("h2", { class: "label" }, "Exposure graph · processes to providers"),
        el("span", { class: "ov-legend" }, "link thickness = events · square = link has findings")));
    const side = el("div", { class: "xg-side" });
    if (!entry.data && entry.status === "error") { card.append(cardError(`Could not load the graph. ${entry.error.message}`, () => store.refresh("graph"))); return el("div", { class: "xg" }, card, side); }
    if (!entry.data) { card.append(el("p", { class: "loading-text loading-text--small", role: "status" }, "Loading the graph…")); return el("div", { class: "xg" }, card, side); }
    const g = entry.data;
    if (!g.nodes.length) { card.append(el("p", { class: "small" }, "No processes have talked to an AI provider yet.")); return el("div", { class: "xg" }, card, side); }
    if (!selectedNode || !g.nodes.some((n) => n.id === selectedNode)) {
      selectedNode = [...g.nodes].filter((n) => n.kind === "process").sort((a, b) => b.risk - a.risk)[0]?.id ?? g.nodes[0].id;
    }
    card.append(el("div", { class: "xg-scroll" }, exposureGraph({ graph: g, selectedId: selectedNode, onSelect: (n) => { selectedNode = n.id; render(); } })));

    const n = g.nodes.find((x) => x.id === selectedNode);
    const mine = g.edges.filter((e) => e.source === n.id || e.target === n.id);
    const events = mine.reduce((s, e) => s + e.event_count, 0);
    const label = (id) => g.nodes.find((x) => x.id === id)?.label ?? id;
    const tools = store.get("tools")?.items ?? [];
    const toolIds = [...new Set(mine.map((e) => e.tool_id))];
    const findings = toolIds.reduce((s, id) => { const t = tools.find((x) => x.tool_id === id); return s + (t ? Object.values(t.finding_counts).reduce((a, b) => a + b, 0) : 0); }, 0);
    const rows = n.kind === "process"
      ? [["Risk band", bandLabel(n.risk_band)], ["Events", fmtNumber(events)], ["Findings", tools.length ? fmtNumber(findings) : "–"], ["Provider", [...new Set(mine.map((e) => label(e.target)))].join(", ") || "–"]]
      : [["Approved", n.sanctioned == null ? "–" : n.sanctioned ? "yes" : "no"], ["Events", fmtNumber(events)], ["Processes", [...new Set(mine.map((e) => label(e.source)))].join(", ") || "–"]];
    const href = n.kind === "process" && toolIds.length === 1 ? `#/alerts?tool=${encodeURIComponent(toolIds[0])}`
      : n.kind === "provider" ? `#/alerts?provider=${encodeURIComponent(n.id.replace(/^prov:/, ""))}` : "#/alerts";
    side.append(
      el("section", { class: "card" }, el("h2", { class: "label" }, "Selected node"),
        el("div", { class: "xg-node" }, n.label),
        el("dl", { class: "pkv xg-kv" }, ...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
        el("a", { class: "btn xg-btn", href }, "View its alerts")),
      el("section", { class: "card" }, el("h2", { class: "label card__label" }, "Legend"),
        el("ul", { class: "xg-legend" },
          el("li", {}, el("span", { class: "xg-key xg-key--line" }), "link, thicker means more events"),
          el("li", {}, el("span", { class: "xg-key xg-key--flag" }, "!"), "link has findings"),
          el("li", {}, el("span", { class: "xg-key xg-key--sel" }), "selected node")),
        el("p", { class: "small" }, "Click a node to open Alerts filtered by that tool or provider.")));
    return el("div", { class: "xg" }, card, side);
  }

  /* ---------- states ---------- */
  function emptyState() {
    return el("section", { class: "card ov-state" },
      el("div", { class: "empty" },
        el("span", { class: "empty__mark hatch", "aria-hidden": "true" }),   // drawn on p9; brand p25 says hatch never marks empty (C-03)
        el("p", { class: "h3" }, "Load a scenario or upload a log."),
        el("div", { class: "empty__actions" },
          P.button({ label: "Load a scenario", onClick: () => runScenario("load", "full_demo") }),
          P.button({ label: "Upload a log", variant: "secondary", onClick: () => { window.location.hash = "#/capture"; } }))));
  }

  function render() {
    const sEntry = store.state("summary");
    const s = sEntry.data;
    if (!s && sEntry.status === "error") {
      root.replaceChildren(el("section", { class: "card ov-state" }, P.errorBlock({ message: `Could not load the summary. ${sEntry.error.message}`, onRetry: () => store.refresh("summary") })));
      return;
    }
    if (!s) { root.replaceChildren(el("section", { class: "card ov-state" }, P.loadingText("Loading the summary…"))); return; }
    if (!s.totals.events && !s.scenario) { root.replaceChildren(emptyState()); return; }

    const alertsTotal = store.get("alerts")?.total;
    root.replaceChildren(
      el("h1", { class: "visually-hidden" }, "Overview"),
      el("div", { class: "ov-top" },
        riskCard(s),
        tile("Events", fmtNumber(s.totals.events)),
        tile("Tools", fmtNumber(s.totals.tools)),
        tile("Providers", fmtNumber(s.totals.providers)),
        tile("Open alerts", fmtNumber(s.totals.alerts_open), alertsTotal != null ? `of ${fmtNumber(alertsTotal)} total` : null, false, s.totals.alerts_open ? "tone-amber" : "tone-green"),
        tile("Unapproved tools", fmtNumber(s.unsanctioned_tools), s.unsanctioned_tools ? "need a decision" : "none waiting", true, s.unsanctioned_tools ? "tone-amber" : "tone-green")),
      el("div", { class: "ov-mid" }, severityCard(s), providerCard(s), timelineCard()),
      feedCard(),
      graphSection());
  }

  const off = watch(store, TOPICS, render);
  let timer = null;
  const soon = () => { if (!timer) timer = setTimeout(() => { timer = null; store.refresh("timeseries"); }, 2000); };
  const offLive = [live.on("event.new", soon), live.on("alert.new", soon), live.on("reset", () => load(store, TOPICS))];
  render();
  load(store, TOPICS);
  return () => { off(); offLive.forEach((f) => f()); clearTimeout(timer); };
}

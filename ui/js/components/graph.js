// Exposure graph (Frontend Design PDF p8): processes on the left, providers on the right.
// Link thickness = events. A teal "!" square on a link = the link has findings. Drawn as SVG; labels via textContent only.
import { el, svg, fmtNumber, bandLabel, bandTone } from "../ui.js";

const W = 1000;
const ROW = 88;
const BOX_W = 212;
const BOX_H = 48;
const LEFT_X = 60;
const RIGHT_X = W - 60 - BOX_W - 160;     // leaves room on the right like the PDF
const TOP = 30;

/** graph: { nodes, edges }. onSelect(node). selectedId: node id. Returns an SVG element. */
export function exposureGraph({ graph, selectedId, onSelect }) {
  const procs = graph.nodes.filter((n) => n.kind === "process").sort((a, b) => b.risk - a.risk);
  const provs = graph.nodes.filter((n) => n.kind === "provider");
  // providers ordered by the events they receive, so the busiest links stay short
  const recv = new Map(provs.map((p) => [p.id, 0]));
  graph.edges.forEach((e) => recv.set(e.target, (recv.get(e.target) ?? 0) + e.event_count));
  provs.sort((a, b) => recv.get(b.id) - recv.get(a.id));

  const rows = Math.max(procs.length, provs.length, 1);
  const H = TOP * 2 + (rows - 1) * ROW + BOX_H;
  const pos = new Map();
  procs.forEach((n, i) => pos.set(n.id, { x: LEFT_X, y: TOP + i * ROW }));
  provs.forEach((n, i) => pos.set(n.id, { x: RIGHT_X, y: TOP + i * ROW }));
  const maxCount = Math.max(1, ...graph.edges.map((e) => e.event_count));

  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "xgraph", role: "group", "aria-label": `Exposure graph: ${procs.length} processes, ${provs.length} providers, ${graph.edges.length} links` });

  const linkLayer = svg("g", {});
  const labelLayer = svg("g", {});
  for (const e of graph.edges) {
    const a = pos.get(e.source); const b = pos.get(e.target);
    if (!a || !b) continue;
    const x1 = a.x + BOX_W, y1 = a.y + BOX_H / 2, x2 = b.x, y2 = b.y + BOX_H / 2;
    const width = 1.5 + 4.5 * Math.sqrt(e.event_count / maxCount);
    linkLayer.append(svg("line", { x1, y1, x2, y2, class: `xgraph__link${e.has_finding ? ` has-finding sev-${e.max_severity ?? "low"}` : ""}`, "stroke-width": width.toFixed(1) }));
    if (e.has_finding || e.event_count >= maxCount * 0.3) {
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      const g = svg("g", { transform: `translate(${mx - 26} ${my - 11})` },
        svg("rect", { width: 52, height: 22, class: "xgraph__count" }),
        svg("text", { x: 26, y: 15.5, "text-anchor": "middle", class: "xgraph__countText", text: fmtNumber(e.event_count) }));
      if (e.has_finding) g.append(svg("rect", { x: 52, width: 22, height: 22, class: `xgraph__flag sev-${e.max_severity ?? "low"}` }), svg("text", { x: 63, y: 16, "text-anchor": "middle", class: "xgraph__flagText", text: "!" }));
      labelLayer.append(g);
    }
  }

  const nodeLayer = svg("g", {});
  for (const n of [...procs, ...provs]) {
    const p = pos.get(n.id);
    const sel = n.id === selectedId;
    const g = svg("g", { transform: `translate(${p.x} ${p.y})`, class: `xgraph__node${sel ? " is-selected" : ""}`, tabindex: "0", role: "button",
      "aria-pressed": String(sel), "aria-label": `${n.label}${n.kind === "process" ? `, risk ${bandLabel(n.risk_band)}` : ""}` },
      svg("rect", { width: BOX_W, height: BOX_H, class: "xgraph__box" }),
      svg("text", { x: 14, y: n.kind === "process" ? 21 : 29, class: "xgraph__name", text: n.label }),
      n.kind === "process" ? svg("text", { x: 14, y: 38, class: `xgraph__sub ${bandTone(n.risk_band)}`, text: `risk ${bandLabel(n.risk_band)}` }) : null);
    g.addEventListener("click", () => onSelect(n));
    g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); onSelect(n); } });
    nodeLayer.append(g);
  }
  root.append(linkLayer, labelLayer, nodeLayer);
  return root;
}

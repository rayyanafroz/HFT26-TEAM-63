// Placeholder for screens that arrive in later phases. Shows live store data so the shell can be checked,
// and the shared state components with ?state=loading|empty|error.
import { el } from "../ui.js";
import { bandLabel } from "../ui.js";

export function mount(container, ctx) {
  const { route, params, store, primitives } = ctx;
  const { emptyBlock, errorBlock, loadingText, card } = primitives;

  const head = el("header", { class: "screen-head" },
    el("div", { class: "label" }, `Phase ${route.phase}`),
    el("h1", { class: "h2" }, route.label),
    el("p", { class: "small" }, `The ${route.label} screen is built in Phase ${route.phase}. The shell, router and live data are working.`));

  const live = el("div", { class: "mono" });
  const paint = () => {
    const entry = store.state("summary");
    if (entry.status === "error" && !entry.data) { live.textContent = `Summary: ${entry.error.message}`; return; }
    const risk = entry.data?.risk;
    live.textContent = risk
      ? `Live check: org risk ${risk.org_risk} (${bandLabel(risk.band)}), compliance score ${risk.compliance_score}`
      : "Live check: loading the summary…";
  };
  paint();
  const off = store.subscribe("summary", paint);

  const body = el("div", { style: "display:grid;gap:16px;max-width:720px" }, card({ label: "Data in the store" }, live));
  if (params.state === "loading") body.append(card({}, loadingText("Loading the summary…")));
  if (params.state === "empty") body.append(card({}, emptyBlock({ message: "Load a scenario or upload a log." })));
  if (params.state === "error") body.append(card({}, errorBlock({ message: `Could not load ${route.label.toLowerCase()}. The local service did not respond.`, onRetry: () => store.refresh("summary") })));

  container.append(head, body);
  return off;
}

// Providers (Frontend Design PDF p15). Approve or unapprove with PUT /api/providers/{id}/sanction;
// the result card shows the risk change the server returned.
import { el, fmtNumber, fmtTime, bandLabel, bandTone } from "../ui.js";
import { watch, load } from "./util.js";

const CATEGORY = { cloud_llm: "Hosted model API", local_llm: "Local model", model_hub: "Model hub", ai_app: "AI app" };

export function mount(container, ctx) {
  const { store, api, primitives: P, toasts } = ctx;
  let seenOnly = true;
  let category = null;
  let busy = null;
  let result = null;    // { name, approved, before, after }

  const seenChip = P.chip({ label: "Seen only", pressed: true, onClick: (n) => { seenOnly = !seenOnly; n.setAttribute("aria-pressed", String(seenOnly)); render(); } });
  const catText = el("span", {}, "Category");
  const catBtn = el("button", { class: "input filters__select filters__select--wide", type: "button", "aria-haspopup": "listbox" }, catText, el("span", { class: "caret", "aria-hidden": "true" }, "▾"));
  const catMenu = el("ul", { class: "menu menu--light", role: "listbox", hidden: true });
  catBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (!catMenu.hidden) { catMenu.hidden = true; return; }
    catMenu.replaceChildren(...[[null, "Any category"], ...Object.entries(CATEGORY)].map(([v, l]) =>
      el("li", { role: "option", tabindex: "0", onClick: () => { category = v; catText.textContent = v ? l : "Category"; catMenu.hidden = true; render(); },
        onKeydown: (ev) => { if (ev.key === "Enter") ev.target.click(); } }, l)));
    catMenu.hidden = false; catMenu.firstElementChild.focus();
  });
  const onDoc = () => { catMenu.hidden = true; };
  document.addEventListener("click", onDoc);

  const tableBox = el("div", { class: "card prov-table" });
  const resultBox = el("div", { "aria-live": "polite" });
  container.append(
    el("header", { class: "screen-head" }, el("h1", { class: "h2" }, "Providers"), el("p", { class: "small" }, "Which AI services are in use, and which you approve.")),
    el("div", { class: "filters" }, el("span", { class: "filters__label filters__label--first" }, "Show"), seenChip, el("div", { style: "position:relative" }, catBtn, catMenu)),
    tableBox, resultBox);

  async function setApproved(p, approved) {
    busy = p.provider_id; render();
    const before = store.get("summary")?.risk;
    try {
      const r = await api.put(`/api/providers/${encodeURIComponent(p.provider_id)}/sanction`, { sanctioned: approved });
      const next = { ...p, ...(r.provider?.provider_id === p.provider_id ? r.provider : {}), sanctioned: approved, sanction_source: "override" };
      store.patch("providers", (old) => old && { ...old, items: old.items.map((x) => (x.provider_id === p.provider_id ? next : x)) });
      store.patch("summary", (old) => old && { ...old, risk: r.risk });
      result = { name: p.display_name, approved, before, after: r.risk };
      ["summary", "tools", "agents"].forEach((t) => store.refresh(t));
    } catch (err) {
      toasts.error(`Could not ${approved ? "approve" : "unapprove"} ${p.display_name}.`, err.message, () => setApproved(p, approved));
    } finally {
      busy = null; render();
    }
  }

  function render() {
    const entry = store.state("providers");
    if (!entry.data && entry.status === "error") {
      tableBox.replaceChildren(el("div", { class: "table-state" }, P.errorBlock({ message: `Could not load providers. ${entry.error.message}`, onRetry: () => store.refresh("providers") })));
      return;
    }
    if (!entry.data) { tableBox.replaceChildren(el("div", { class: "table-state" }, P.loadingText("Loading providers…"))); return; }
    const items = entry.data.items.filter((p) => (!seenOnly || p.seen) && (!category || p.category === category))
      .sort((a, b) => b.event_count - a.event_count);
    const head = el("thead", {}, el("tr", {}, ...["Provider", "Category", "Events", "Tools", "Last seen", "Seen", "Approved", ""].map((h) =>
      el("th", { scope: "col" }, h || el("span", { class: "visually-hidden" }, "Links")))));
    const body = el("tbody", {}, ...items.map((p) => el("tr", {},
      el("th", { scope: "row", class: "prov__name" }, p.display_name),
      el("td", {}, CATEGORY[p.category] ?? p.category),
      el("td", {}, fmtNumber(p.event_count)),
      el("td", {}, fmtNumber(p.tool_count)),
      el("td", { class: "mono-cell mono-cell--ink" }, fmtTime(p.last_seen)),
      el("td", {}, p.seen ? P.stateCell(p.confirmed ? "used" : "granted", { label: p.confirmed ? "confirmed" : "unconfirmed" }) : el("span", { class: "small" }, "not seen")),
      el("td", {}, P.toggle({ checked: p.sanctioned, disabled: busy === p.provider_id, label: p.sanctioned ? "approved" : "not approved",
        name: `approve-${p.provider_id}`, onChange: (v) => setApproved(p, v) })),
      el("td", {}, el("a", { class: "monolink", href: `#/alerts?provider=${encodeURIComponent(p.provider_id)}` }, "Alerts")))));
    tableBox.replaceChildren(el("div", { class: "table-scroll" }, el("table", { class: "table prov" }, head, body)));
    if (!items.length) tableBox.append(el("p", { class: "table-none" }, entry.data.items.length ? "No providers match these filters." : "No providers seen yet."));

    resultBox.replaceChildren(result ? el("section", { class: "result-strip" },
      el("div", {},
        el("h2", { class: "label" }, "Result of your change (from the server)"),
        el("div", { class: "result-strip__line" },
          el("span", {}, `AI Risk ${result.before ? `${result.before.org_risk} → ` : ""}${result.after.org_risk}`),
          el("strong", { class: bandTone(result.after.band) }, bandLabel(result.after.band)))),
      el("p", { class: "small" }, `${result.name} ${result.approved ? "approved" : "no longer approved"}. Scores updated on every screen.`)) : "");
  }

  const off = watch(store, ["providers"], render);
  render();
  load(store, ["providers", "summary"]);
  return () => { off(); document.removeEventListener("click", onDoc); };
}

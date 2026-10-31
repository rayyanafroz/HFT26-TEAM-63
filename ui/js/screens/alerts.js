// Alerts (Frontend Design PDF p10) and the alert detail panel (p11).
// Close alert has no endpoint yet, so it is shown disabled (UD-18). Findings mode lists /api/findings.
import { el, fmtTime, fmtNumber, sevTone } from "../ui.js";
import { watch, load, byNewest, namer } from "./util.js";
import { ruleName, owaspName, sourceName } from "../rules.js";
import { overlayIn, overlayOut } from "../motion.js";

const SEVS = ["critical", "high", "medium", "low"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const PAGE = 100;
const VERDICT = { true_positive: "Confirmed", likely_false_positive: "Likely false positive", needs_review: "Needs review" };
const LOCATION = { body: "body", path: "path", "header:authorization": "Authorization header", "header:x-api-key": "x-api-key header",
  tool_call: "tool call", tool_declaration: "tool declaration", tool_result: "tool result" };

export function mount(container, ctx) {
  const { store, api, primitives: P, toasts } = ctx;
  const f = { mode: "alerts", sev: new Set(), status: new Set(), tool: null, provider: null, control: null, rule: null, q: "", page: 0 };
  let selected = null;
  let panelClose = null;
  let busy = null;

  function applyParams(params) {
    if (params.tool) f.tool = params.tool;
    if (params.provider) f.provider = params.provider;
    if (params.control) { f.control = params.control; store.refresh("compliance"); }
    if (params.severity) f.sev = new Set(params.severity.split(","));
    selected = params.alert ?? null;
  }
  applyParams(ctx.params);

  /* ---------- filter bar ---------- */
  const modeSeg = P.segmented({ items: [{ id: "alerts", label: "Alerts" }, { id: "findings", label: "Findings" }], selected: "alerts",
    onSelect: (id) => { f.mode = id; f.page = 0; if (id === "findings") store.refresh("findings"); renderTable(); } });
  const sevChips = SEVS.map((s) => P.chip({ label: SEV_LABEL[s], pressed: false, onClick: (n) => toggle(f.sev, s, n) }));
  const statusChips = [["open", "Open"], ["acked", "Acknowledged"]].map(([s, l]) => P.chip({ label: l, onClick: (n) => toggle(f.status, s, n) }));
  function toggle(set, v, node) {
    set.has(v) ? set.delete(v) : set.add(v);
    node.setAttribute("aria-pressed", String(set.has(v)));
    f.page = 0; renderTable();
  }
  const toolSel = dropdown("Tool", () => (store.get("tools")?.items ?? []).map((t) => [t.tool_id, t.display_name]), (v) => { f.tool = v; f.page = 0; renderTable(); });
  const ruleSel = dropdown("Rule", () => [...new Set((store.get("alerts")?.items ?? []).map((a) => a.rule_id))].sort().map((r) => [r, ruleName(r)]),
    (v) => { f.rule = v; f.page = 0; renderTable(); });
  const search = P.searchInput({ placeholder: "Search alerts", onInput: (v) => { f.q = v.trim().toLowerCase(); f.page = 0; renderTable(); } });
  search.classList.add("filters__search");
  search.id = "alerts-search";

  const bar = el("div", { class: "filters", role: "toolbar", "aria-label": "Filters" },
    modeSeg,
    el("span", { class: "filters__label" }, "Severity"), ...sevChips,
    el("span", { class: "filters__label" }, "Status"), ...statusChips,
    toolSel.node, ruleSel.node, search);

  const tableBox = el("div", { class: "card alerts-table" });
  const foot = el("div", { class: "pager" });
  const providerNote = el("div", {});
  container.append(
    el("header", { class: "screen-head" }, el("h1", { class: "h2" }, "Alerts"), el("p", { class: "small" }, "Everything that was flagged, newest first.")),
    bar, providerNote, tableBox, foot);

  /* Select-style dropdown with a "Any" option. Contents are not drawn in the design (UD-19). */
  function dropdown(label, options, onPick) {
    const text = el("span", {}, label);
    const trigger = el("button", { class: "input filters__select", type: "button", "aria-haspopup": "listbox" }, text, el("span", { "aria-hidden": "true", class: "caret" }, "▾"));
    const menu = el("ul", { class: "menu menu--light", role: "listbox", hidden: true });
    const wrap = el("div", { style: "position:relative" }, trigger, menu);
    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!menu.hidden) { menu.hidden = true; return; }
      menu.replaceChildren(...[[null, `Any ${label.toLowerCase()}`], ...options()].map(([v, l]) =>
        el("li", { role: "option", tabindex: "0", onClick: () => { menu.hidden = true; text.textContent = v ? l : label; onPick(v); },
          onKeydown: (ev) => { if (ev.key === "Enter") ev.target.click(); } }, l)));
      menu.hidden = false;
      menu.firstElementChild?.focus();
    });
    document.addEventListener("click", () => { menu.hidden = true; });
    return { node: wrap, set: (v, l) => { text.textContent = v ? l : label; } };
  }

  /* ---------- data ---------- */
  function filtered() {
    const items = byNewest(store.get("alerts")?.items ?? []);
    const ctl = f.control ? store.get("compliance")?.controls.find((c) => c.id === f.control) : null;
    const ctlIds = ctl ? new Set(ctl.finding_ids) : null;
    return items.filter((a) =>
      (!f.sev.size || f.sev.has(a.severity)) &&
      (!f.status.size || f.status.has(a.status)) &&
      (!f.tool || a.tool_id === f.tool) &&
      (!f.provider || a.provider_id === f.provider) &&
      (!f.control || (ctlIds ? ctlIds.has(a.finding_id) : true)) &&
      (!f.rule || a.rule_id === f.rule) &&
      (!f.q || `${a.title} ${a.rule_id}`.toLowerCase().includes(f.q)));
  }

  function renderTable() {
    const entry = store.state(f.mode === "alerts" ? "alerts" : "findings");
    const toolName = namer(store.get("tools"), "tool_id");
    const provName = namer(store.get("providers"), "provider_id");
    const notes = [];
    if (f.provider) notes.push(el("div", { class: "filter-note" }, `Provider: ${provName(f.provider)}`, el("button", { class: "linkbtn", type: "button", onClick: () => { f.provider = null; renderTable(); } }, "Clear")));
    if (f.control) notes.push(el("div", { class: "filter-note" }, `Control: ${f.control}`, el("button", { class: "linkbtn", type: "button", onClick: () => { f.control = null; renderTable(); } }, "Clear")));
    providerNote.replaceChildren(...notes);
    if (f.tool) toolSel.set(f.tool, toolName(f.tool));

    if (!entry.data && entry.status === "error") {
      tableBox.replaceChildren(el("div", { class: "table-state" }, P.errorBlock({ message: `Could not load ${f.mode}. ${entry.error.message}`, onRetry: () => store.refresh(f.mode) })));
      foot.replaceChildren(); return;
    }
    if (!entry.data) { tableBox.replaceChildren(el("div", { class: "table-state" }, P.loadingText(`Loading ${f.mode}…`))); foot.replaceChildren(); return; }

    if (f.mode === "findings") { renderFindings(entry.data, toolName); return; }

    const rows = filtered();
    const total = rows.length;
    const pageRows = rows.slice(f.page * PAGE, f.page * PAGE + PAGE);
    if (!store.get("alerts").items.length) {
      tableBox.replaceChildren(el("div", { class: "table-state" }, P.emptyBlock({ message: "No alerts yet. Load a scenario or upload a log." })));
      foot.replaceChildren(); return;
    }
    const head = el("thead", {}, el("tr", {}, ...["Severity", "Title", "Tool", "Provider", "Status", "Source", "Time"].map((h) => el("th", { scope: "col" }, h))));
    const body = el("tbody", {}, ...pageRows.map((a) => {
      const tr = el("tr", { class: `is-clickable${a.id === selected ? " is-selected" : ""}`, dataset: { id: a.id } },
        el("td", {}, P.sevMark(a.severity)),
        el("td", { class: `alerts__title${a.severity === "critical" || a.severity === "high" ? " is-strong" : ""}` },
          el("a", { href: `#/alerts?alert=${encodeURIComponent(a.id)}` }, a.title)),
        el("td", {}, toolName(a.tool_id)),
        el("td", {}, provName(a.provider_id)),
        el("td", {}, el("span", { class: `tag tag--status tag--${a.status === "acked" ? "acked" : "open"}` }, a.status === "acked" ? "ack" : "open")),
        el("td", { class: "mono-cell" }, sourceName(a.source ?? a.finding?.source)),
        el("td", { class: "mono-cell" }, fmtTime(a.created_at)));
      tr.addEventListener("click", (e) => { if (!e.target.closest("a")) location.hash = `#/alerts?alert=${encodeURIComponent(a.id)}`; });
      return tr;
    }));
    const table = el("table", { class: "table alerts" },
      el("colgroup", {}, ...[11.5, 31.4, 14.1, 11.9, 7.7, 14.5, 8.9].map((w) => el("col", { style: `width:${w}%` }))), head, body);
    tableBox.replaceChildren(el("div", { class: "table-scroll" }, table));
    if (!total) tableBox.append(el("p", { class: "table-none" }, "No alerts match these filters."));
    pager(total);
  }

  function renderFindings(data, toolName) {
    const items = byNewest(data.items ?? []).filter((x) =>
      (!f.sev.size || f.sev.has(x.severity)) && (!f.tool || x.tool_id === f.tool) && (!f.rule || x.rule_id === f.rule) &&
      (!f.q || `${ruleName(x.rule_id)} ${x.rule_id}`.toLowerCase().includes(f.q)));
    const pageRows = items.slice(f.page * PAGE, f.page * PAGE + PAGE);
    const table = el("table", { class: "table alerts" },
      el("thead", {}, el("tr", {}, ...["Severity", "Rule", "Category", "Tool", "Location", "Time"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, ...pageRows.map((x) => el("tr", {},
        el("td", {}, P.sevMark(x.severity)),
        el("td", { class: "alerts__title is-strong" }, ruleName(x.rule_id)),
        el("td", {}, x.category),
        el("td", {}, toolName(x.tool_id)),
        el("td", { class: "mono-cell" }, LOCATION[x.location?.field] ?? x.location?.field ?? "–"),
        el("td", { class: "mono-cell" }, fmtTime(x.created_at))))));
    tableBox.replaceChildren(el("div", { class: "table-scroll" }, table));
    if (!items.length) tableBox.append(el("p", { class: "table-none" }, "No findings match these filters."));
    pager(items.length);
  }

  function pager(total) {
    const from = total ? f.page * PAGE + 1 : 0;
    const to = Math.min(total, (f.page + 1) * PAGE);
    foot.replaceChildren(
      el("span", { class: "pager__text" }, `Showing ${from} to ${to} of ${fmtNumber(total)} · ${PAGE} per page`),
      el("span", { class: "pager__btns" },
        P.button({ label: "Previous", variant: "small", disabled: f.page === 0, onClick: () => { f.page--; renderTable(); } }),
        P.button({ label: "Next", variant: "small", disabled: to >= total, onClick: () => { f.page++; renderTable(); } })));
  }

  /* ---------- detail panel ---------- */
  function openPanel() {
    const alert = (store.get("alerts")?.items ?? []).find((a) => a.id === selected);
    if (!alert) { closePanelDom(); return; }
    const toolName = namer(store.get("tools"), "tool_id");
    const provName = namer(store.get("providers"), "provider_id");
    const fd = alert.finding ?? {};
    const rem = alert.remediation;
    const kv = (rows) => el("dl", { class: "pkv" }, ...rows.filter(Boolean).flatMap(([k, v, mono, tone]) => [el("dt", {}, k), el("dd", { class: `${mono ? "mono" : ""} ${tone ?? ""}` }, v)]));

    const evidence = el("section", { class: "panel__sec" },
      el("h3", { class: "label" }, "Evidence"),
      kv([
        ["Rule", `${alert.rule_id} · ${ruleName(alert.rule_id)}`, true],
        fd.masked_preview ? ["Masked value", fd.masked_preview, true] : null,
        fd.meta?.context ? ["Context", contextNode(fd.meta.context), true] : null,
        fd.owasp?.length ? ["OWASP", fd.owasp.map(owaspName).join(", "), true] : null,
        fd.location ? ["Location", LOCATION[fd.location.field] ?? fd.location.field, true] : null,
      ]));

    let remediation;
    if (rem) {
      remediation = el("section", { class: "panel__sec" },
        el("h3", { class: "label" }, "Remediation"),
        el("p", { class: "panel__text" }, rem.summary),
        rem.steps?.length ? el("ol", { class: "panel__steps" }, ...rem.steps.map((s) => el("li", {}, s))) : null,
        kv([
          ["Sensitivity", SEV_LABEL[rem.sensitivity] ?? rem.sensitivity, false, sevTone(rem.sensitivity)],
          ["Verdict", VERDICT[rem.verdict] ?? rem.verdict, false, { true_positive: "tone-red", likely_false_positive: "tone-green", needs_review: "tone-amber" }[rem.verdict]],
          ["Triage mode", rem.source === "llm" ? "LLM" : "Template", true],
          ["Redaction check", rem.redaction_check.replace("_", " "), true, { passed: "tone-green", blocked: "tone-red" }[rem.redaction_check]],
        ]));
    } else {
      remediation = el("section", { class: "panel__sec" }, el("h3", { class: "label" }, "Remediation"),
        el("p", { class: "panel__text" }, busy === "remediate" ? "Asking for a remediation…" : "No remediation yet. Remediate asks the triage model, or a local template, for steps."));
    }

    const receivedBody = el("div", { class: "panel__received", hidden: true },
      rem?.prompt_text ? P.codeBlock(rem.prompt_text)
        : el("p", { class: "panel__text" }, !rem ? "Nothing has been sent for this alert."
          : rem.redaction_check === "blocked" ? "Nothing was sent. The redaction check found a secret in the text and blocked the call."
          : "Nothing was sent. Triage used a local template."));
    const receivedBtn = el("button", { class: "panel__toggle label", type: "button", "aria-expanded": "false" }, "What the AI model received ", el("span", { "aria-hidden": "true" }, "▾"));
    receivedBtn.addEventListener("click", () => {
      receivedBody.hidden = !receivedBody.hidden;
      receivedBtn.setAttribute("aria-expanded", String(!receivedBody.hidden));
    });
    if (rem) { receivedBody.hidden = false; receivedBtn.setAttribute("aria-expanded", "true"); }

    const closeBtn = el("button", { class: "panel__close", type: "button", onClick: () => { location.hash = "#/alerts"; } }, "Close ×");
    const acked = alert.status === "acked";
    const panel = el("aside", { class: "panel", role: "dialog", "aria-modal": "true", "aria-labelledby": "panel-title" },
      el("div", { class: "panel__scroll" },
        el("div", { class: "panel__top" }, el("div", { class: "label" }, "Alert detail"), closeBtn),
        el("h2", { class: "panel__title", id: "panel-title", tabindex: "-1" }, alert.title),
        el("div", { class: "panel__sev" }, P.sevMark(alert.severity), el("span", { class: `tag tag--status tag--${acked ? "acked" : "open"}` }, acked ? "ack" : "open")),
        el("div", { class: "panel__meta" }, [toolName(alert.tool_id), provName(alert.provider_id), sourceName(alert.source ?? fd.source), fmtTime(alert.created_at)].filter((x) => x && x !== "–").join(" · ")),
        evidence, remediation,
        el("section", { class: "panel__sec" }, receivedBtn, receivedBody)),
      el("div", { class: "panel__actions" },
        P.button({ label: busy === "remediate" ? "Remediating…" : "Remediate", disabled: !!busy, onClick: () => act("remediate", alert) }),
        P.button({ label: acked ? "Acknowledged" : busy === "ack" ? "Acknowledging…" : "Acknowledge", variant: "secondary", disabled: acked || !!busy, onClick: () => act("ack", alert) }),
        el("span", { class: "panel__closealert" },
          P.button({ label: "Close alert", variant: "secondary", disabled: true, ariaLabel: "Close alert. Not available yet" }),
          el("span", { class: "panel__hint" }, "Not available yet"))));

    const firstOpen = !panelClose;
    closePanelDom(true);
    const scrim = el("div", { class: "panel-scrim", onClick: () => { location.hash = "#/alerts"; } });
    document.body.append(scrim, panel);
    const onKey = (e) => { if (e.key === "Escape") location.hash = "#/alerts"; };
    document.addEventListener("keydown", onKey);
    const opener = firstOpen ? document.activeElement : panelClose?.opener;
    panelClose = Object.assign((animate) => {
      document.removeEventListener("keydown", onKey);
      if (!animate) { scrim.remove(); panel.remove(); return; }
      scrim.style.pointerEvents = "none"; panel.style.pointerEvents = "none";
      overlayOut([scrim], {}, () => scrim.remove());
      overlayOut([panel], { x: 40 }, () => panel.remove());
    }, { opener });
    if (firstOpen) { overlayIn(scrim, panel, { x: 40 }); panel.querySelector("#panel-title").focus(); }
  }

  function closePanelDom(keepOpener) {
    if (!panelClose) return;
    const opener = panelClose.opener;
    panelClose(!keepOpener); panelClose = null;      // animate only when the panel really closes
    if (!keepOpener) opener?.focus?.();
  }

  /** Context text with [REDACTED] markers drawn as redaction blocks. */
  function contextNode(text) {
    const parts = String(text).split(/(\[REDACTED\])/);
    return el("span", {}, ...parts.map((p) => (p === "[REDACTED]" ? P.redaction({ width: 150 }) : p)));
  }

  async function act(kind, alert) {
    busy = kind; openPanel();
    try {
      if (kind === "ack") {
        const updated = await api.post(`/api/alerts/${encodeURIComponent(alert.id)}/ack`);
        replaceAlert({ ...alert, status: updated?.status ?? "acked", acked_at: updated?.acked_at ?? new Date().toISOString() });
      } else {
        const rem = await api.post(`/api/alerts/${encodeURIComponent(alert.id)}/remediate`);
        replaceAlert({ ...alert, remediation: rem });
      }
      store.refresh("summary");
    } catch (err) {
      toasts.error(kind === "ack" ? "Could not acknowledge the alert." : "Could not get a remediation.", err.message, () => act(kind, alert));
    } finally {
      busy = null; if (selected === alert.id) openPanel();
    }
  }
  function replaceAlert(next) {
    store.patch("alerts", (old) => old && { ...old, items: old.items.map((a) => (a.id === next.id ? next : a)) });
  }

  /* ---------- wiring ---------- */
  function renderAll() {
    renderTable();
    if (selected && store.get("alerts")) openPanel(); else closePanelDom();
  }
  const off = watch(store, ["alerts", "findings", "tools", "providers", "compliance"], renderAll);
  const offLive = ctx.live.on("remediation.update", (rem) =>
    store.patch("alerts", (old) => old && { ...old, items: old.items.map((a) => (a.id === rem.alert_id ? { ...a, remediation: rem } : a)) }));
  renderAll();
  load(store, ["alerts", "tools", "providers"]);
  return {
    update(params) { applyParams(params); renderAll(); },
    unmount() { off(); offLive(); closePanelDom(true); },
  };
}

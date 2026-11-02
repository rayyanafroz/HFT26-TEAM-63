// The options page: protection settings, a place to try the guard, the "not a secret" list, company
// terms, and the history.

import { ACTION_LABELS, actionTone, ask, h, sevTone, siteName, when } from "../pages/common.js";
import { ruleInfo } from "../shared/rules.js";

const MODES = [["protect", "Protect"], ["warn", "Warn only"], ["off", "Off"]];
const ACTIONS = [["block", "Block"], ["warn", "Warn"], ["note", "Note"], ["allow", "Nothing"]];
const SEVERITIES = [["critical", "Critical (private keys, cloud and payment keys)"], ["high", "High (API keys, cards, IDs)"], ["medium", "Medium (passwords, PAN, confidential code)"], ["low", "Low (emails, phones, random strings)"]];

let state = null;

async function save(change) {
  state.policy = (await ask("setPolicy", { change })).policy;
  renderPolicy();
}

function select(options, value, onChange) {
  const el = h("select", { onchange: (e) => onChange(e.target.value) }, options.map(([v, label]) => h("option", { value: v }, label)));
  el.value = value;
  return el;
}

function renderPolicy() {
  const p = state.policy;
  document.getElementById("enabled").checked = p.enabled;
  for (const key of ["allowOverride", "requireReason", "scanPaste", "scanFiles", "hiddenText", "companion"]) {
    document.getElementById(key).checked = p[key];
  }
  document.querySelector("#sites tbody").replaceChildren(...state.sites.map((s) =>
    h("tr", {},
      h("td", {}, h("b", {}, s.name), h("div", { class: "muted small" }, s.hosts.join(", "), s.adapter === "generic" ? " · best effort" : "")),
      h("td", {}, select(MODES, p.sites[s.id], (mode) => save({ sites: { ...p.sites, [s.id]: mode } }))))));
  document.querySelector("#actions tbody").replaceChildren(...SEVERITIES.map(([sev, label]) =>
    h("tr", {}, h("td", {}, label), h("td", {}, select(ACTIONS, p.actions[sev], (a) => save({ actions: { ...p.actions, [sev]: a } }))))));
  document.getElementById("internal_markers").value = p.engine.internal_markers.join("\n");
  document.getElementById("email_skip_domains").value = p.engine.email_skip_domains.join("\n");
  const allow = document.getElementById("allowlist");
  allow.replaceChildren(...p.allowlist.map((e, i) =>
    h("tr", {},
      h("td", {}, ruleInfo(e.rule_id).title),
      h("td", {}, h("span", { class: "mono" }, e.masked_preview || "")),
      h("td", {}, e.added ? when(e.added) : ""),
      h("td", {}, h("button", { class: "btn", type: "button", onclick: () => save({ allowlist: p.allowlist.filter((_, j) => j !== i) }) }, "Remove")))));
  if (!p.allowlist.length) allow.append(h("tr", {}, h("td", { colspan: "4", class: "empty" }, "Nothing here. Use “Not a secret” in the guard to add a value.")));
}

async function renderHistory() {
  const { history } = await ask("getHistory", { limit: 500 });
  const body = document.getElementById("events");
  body.replaceChildren(...history.map((e) =>
    h("tr", {},
      h("td", { class: "mono" }, new Date(e.at).toLocaleString()),
      h("td", {}, siteName(state.sites, e.site)),
      h("td", {}, h("span", { class: `tag ${actionTone(e.action)}` }, ACTION_LABELS[e.action] ?? e.action), " ", h("span", { class: "muted small" }, e.kind),
        e.reason ? h("div", { class: "muted small" }, `“${e.reason}”`) : null),
      h("td", {}, e.findings.map((f) => h("div", {}, h("span", { class: `tag ${sevTone(f.severity)}` }, f.severity || "–"), " ",
        ruleInfo(f.rule_id).title, " ", h("span", { class: "mono muted" }, f.masked_preview)))))));
  if (!history.length) body.append(h("tr", {}, h("td", { colspan: "4", class: "empty" }, "No events yet.")));
}

let tryTimer = null;
async function tryText() {
  const text = document.getElementById("try-text").value;
  const out = document.getElementById("try-result");
  if (!text.trim()) return out.replaceChildren();
  const result = await ask("tryText", { text });
  const what = { allow: "Nothing found: this would go through.", note: "Would go through, with a quiet note.", warn: "Would stop and ask first.", block: "Would be stopped." }[result.decision.action];
  out.replaceChildren(
    h("p", {}, h("b", {}, what)),
    h("ul", {}, result.findings.map((f) => h("li", {},
      h("span", { class: `tag ${sevTone(f.severity)}` }, f.severity), h("b", {}, f.title), h("span", { class: "mono muted" }, f.masked_preview ?? "")))),
    result.findings.length ? h("div", { class: "out", "aria-label": "What the AI would receive" }, h("span", { class: "label" }, "What the AI would receive after “Redact”"), "\n", preview(text, result.findings)) : null);
}

/** The redacted text, without touching any tab's vault: numbered per rule, for display only. */
function preview(text, findings) {
  const counters = {};
  const names = new Map();
  const edits = findings.filter((f) => f.redactable).flatMap((f) => (f.ranges ?? []).map(([a, b]) => ({ a, b, f }))).sort((x, y) => x.a - y.a);
  let out = "";
  let cursor = 0;
  for (const { a, b, f } of edits) {
    if (a < cursor) continue;
    const key = `${f.rule_id}:${f.hash12}`;
    if (!names.has(key)) {
      counters[f.placeholder] = (counters[f.placeholder] ?? 0) + 1;
      names.set(key, `[${f.placeholder}_${counters[f.placeholder]}]`);
    }
    out += text.slice(cursor, a) + names.get(key);
    cursor = b;
  }
  return out + text.slice(cursor);
}

async function main() {
  state = await ask("getState");
  renderPolicy();
  renderHistory();
  document.getElementById("enabled").addEventListener("change", (e) => save({ enabled: e.target.checked }));
  for (const key of ["allowOverride", "requireReason", "scanPaste", "scanFiles", "hiddenText", "companion"]) {
    document.getElementById(key).addEventListener("change", (e) => save({ [key]: e.target.checked }));
  }
  document.getElementById("save-terms").addEventListener("click", async () => {
    const lines = (id) => document.getElementById(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
    await save({ engine: { internal_markers: lines("internal_markers"), email_skip_domains: lines("email_skip_domains") } });
    document.getElementById("terms-saved").textContent = "Saved.";
    setTimeout(() => (document.getElementById("terms-saved").textContent = ""), 2000);
  });
  document.getElementById("try-text").addEventListener("input", () => {
    clearTimeout(tryTimer);
    tryTimer = setTimeout(tryText, 200);
  });
  document.getElementById("export").addEventListener("click", async () => {
    const { history } = await ask("getHistory", { limit: 1000 });
    const url = URL.createObjectURL(new Blob([JSON.stringify(history, null, 2)], { type: "application/json" }));
    h("a", { href: url, download: `shadow-lens-history-${new Date().toISOString().slice(0, 10)}.json` }).click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  document.getElementById("clear").addEventListener("click", async () => {
    if (!confirm("Clear the whole history? This cannot be undone.")) return;
    await ask("clearHistory");
    renderHistory();
  });
  if (state.policy.companion) {
    ask("companionStatus").then((s) => {
      document.getElementById("companion-status").textContent = s.connected
        ? `Dashboard connected (version ${s.info?.version ?? "?"}).`
        : "The dashboard is not installed on this computer. Run: python -m shadowlens.native_host install";
    });
  }
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.history) renderHistory();
  });
}

main();

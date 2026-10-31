// Global bar and status strip (Frontend Design PDF p4). Both are on every screen.
import { el, fmtNumber, pct } from "../ui.js";
import { logo, button } from "./primitives.js";

/* ---------- small dropdown used by the scenario select and the outbound-hosts note ---------- */
function attachMenu(trigger, menu) {
  const close = () => { menu.hidden = true; trigger.setAttribute("aria-expanded", "false"); };
  const open = () => { menu.hidden = false; trigger.setAttribute("aria-expanded", "true"); };
  trigger.setAttribute("aria-expanded", "false");
  trigger.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden ? open() : close(); });
  document.addEventListener("click", (e) => { if (!menu.contains(e.target)) close(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !menu.hidden) { close(); trigger.focus(); } });
  return { open, close };
}

/* ---------- Global bar ---------- */
export function globalBar({ routes, scenarios, onLoad, onPlay, onReset }) {
  const links = routes.filter((r) => r.ready).map((r) =>
    el("a", { class: "navlink", href: `#/${r.id}`, dataset: { route: r.id } }, r.label));

  let selected = scenarios[0];
  const selLabel = el("span", {}, selected);
  const trigger = el("button", { class: "scenario__select", type: "button", "aria-haspopup": "listbox", "aria-label": "Scenario" },
    selLabel, el("span", { class: "caret", "aria-hidden": "true" }, "▾"));
  const menu = el("ul", { class: "menu", role: "listbox", hidden: true, "aria-label": "Scenarios" },
    ...scenarios.map((name) => el("li", { role: "option", "aria-selected": String(name === selected), tabindex: "0", dataset: { name } }, name)));
  const dd = attachMenu(trigger, menu);
  menu.addEventListener("click", (e) => {
    const li = e.target.closest("li"); if (!li) return;
    selected = li.dataset.name; selLabel.textContent = selected;
    menu.querySelectorAll("li").forEach((x) => x.setAttribute("aria-selected", String(x === li)));
    dd.close();
  });

  const bLoad = button({ label: "Load", variant: "small", onClick: () => onLoad(selected) });
  const bPlay = button({ label: "Play", variant: "small", onClick: () => onPlay(selected) });
  const bReset = button({ label: "Reset", variant: "small", onClick: () => onReset() });

  const node = el("header", { class: "gbar", role: "banner" },
    el("a", { href: "#/home", "aria-label": "ShadowLens, go to Home", style: "text-decoration:none;flex:none" }, logo({ night: true, size: 28 })),
    el("nav", { class: "gbar__nav", "aria-label": "Main" }, ...links),
    el("div", { class: "scenario" },
      el("span", { class: "scenario__label" }, "Scenario"),
      el("div", { style: "position:relative" }, trigger, menu),
      bLoad, bPlay, bReset));

  return {
    node,
    setActive(id) {
      node.querySelectorAll(".navlink").forEach((a) => {
        if (a.dataset.route === id) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
      });
    },
    setBusy(busy) { [bLoad, bPlay, bReset].forEach((b) => { b.disabled = busy; }); },
  };
}

/* ---------- Status strip ---------- */
const LIVE_LABEL = { live: "Live", reconnecting: "Reconnecting", connecting: "Connecting", mock: "Mock data" };

export function statusStrip() {
  const hostsBtn = el("button", { class: "strip__host", type: "button", "aria-haspopup": "true" });
  const hostsNote = el("div", { class: "menu menu--note", hidden: true, role: "note" });
  attachMenu(hostsBtn, hostsNote);

  const ai = el("span", { class: "strip__item" });
  const triage = el("span", { class: "strip__item" });
  const covSeen = el("span", { class: "strip__cov-seen" });
  const covNum = el("b", {}, "–");
  const cov = el("span", { class: "strip__item" }, "Coverage",
    el("span", { class: "strip__cov", role: "img", "aria-label": "Coverage" }, covSeen, el("span", { class: "strip__cov-unseen" })), covNum);
  const liveText = el("span", {}, "Connecting");
  const liveEl = el("span", { class: "strip__live", dataset: { state: "connecting" } }, el("i", { "aria-hidden": "true" }), liveText);
  const tag = el("span", { class: "strip__tag", hidden: true }, "Illustrative data");

  const node = el("div", { class: "strip", role: "status", "aria-label": "Status" },
    el("span", { class: "strip__item" }, hostsBtn), hostsNote, ai, triage, cov, liveEl, tag);

  const dash = () => "–";
  return {
    node,
    /** health: /api/health. summary: /api/stats/summary. Either may be null before the first load. */
    update({ health, summary, conn, illustrative, protectionOn = true }) {
      const hosts = health?.llm?.enabled && health?.llm?.key_present ? 1 : 0;   // count of outbound hosts is not in the API (UD-09)
      hostsBtn.replaceChildren(el("b", {}, "Local only"), ` · ${health ? hosts : dash()} outbound host${hosts === 1 ? "" : "s"} `, el("span", { "aria-hidden": "true" }, "▾"));
      hostsNote.replaceChildren(
        el("strong", {}, "Only redacted text leaves this computer."),
        el("div", { style: "margin-top:6px" }, hosts
          ? "The triage model receives redacted text for each alert. Nothing else is sent."
          : "No outbound hosts. Triage uses local templates."));
      const llm = summary?.llm;
      ai.replaceChildren("AI calls ", el("b", {}, llm ? String(llm.sent) : dash()), " sent · ", el("b", {}, llm ? String(llm.blocked) : dash()), " blocked");
      triage.replaceChildren("Triage ", el("b", {}, health ? (health.llm.mode === "llm" ? "LLM" : "Template") : dash()));
      const c = summary?.coverage;
      const total = c ? c.full + c.metadata_only : 0;
      const p = total && protectionOn ? pct(c.full, total) : 0;   // p5: 0% while protection is off
      covSeen.style.width = `${p}%`;
      covNum.textContent = c || !protectionOn ? `${p}%` : dash();
      liveEl.dataset.state = conn;
      liveText.textContent = LIVE_LABEL[conn] ?? conn;
      tag.hidden = !illustrative;
    },
  };
}

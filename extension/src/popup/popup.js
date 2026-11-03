// The toolbar popup: protection on the current site, today's numbers, the latest events.

import { ACTION_LABELS, actionTone, ask, h, siteName, when } from "../pages/common.js";
import { siteForHost } from "../shared/sites.js";

const STOPPED = ["cancelled", "redacted", "cleaned"];
const ANYWAY = ["sent_anyway", "pasted_anyway", "uploaded_anyway", "sent_unchecked"];

const MODE_HELP = {
  protect: "Secrets are stopped before they are pasted, sent or uploaded.",
  warn: "You are warned, but nothing is ever blocked.",
  off: "Nothing is checked on this site.",
};

async function render() {
  const [{ policy, stats, history, sites }, [tab]] = await Promise.all([ask("getState"), chrome.tabs.query({ active: true, currentWindow: true })]);
  const status = document.getElementById("status");
  status.querySelector(".dot").className = `dot ${policy.enabled ? "on" : "off"}`;
  status.lastChild.textContent = policy.enabled ? "On" : "Paused";

  let host = "";
  try {
    host = new URL(tab?.url ?? "").host;
  } catch {
    /* not a web page */
  }
  const site = siteForHost(host);
  document.getElementById("site").hidden = !site;
  document.getElementById("elsewhere").hidden = !!site;
  if (site) {
    const mode = policy.enabled ? policy.sites[site.id] : "off";
    document.getElementById("site-name").textContent = site.name;
    document.getElementById("site-help").textContent = policy.enabled ? MODE_HELP[mode] : "Shadow Lens is paused everywhere (Settings).";
    for (const button of document.querySelectorAll("[data-mode]")) {
      button.setAttribute("aria-pressed", String(button.dataset.mode === mode));
      button.onclick = async () => {
        await ask("setPolicy", { change: { enabled: true, sites: { ...policy.sites, [site.id]: button.dataset.mode } } });
        render();
      };
    }
  } else {
    document.getElementById("site-list").textContent = sites.map((s) => s.name).join(", ");
  }

  const sum = (keys) => keys.reduce((n, k) => n + (stats.today[k] ?? 0), 0);
  document.getElementById("n-stopped").textContent = sum(STOPPED);
  document.getElementById("n-redacted").textContent = sum(["redacted", "cleaned"]);
  document.getElementById("n-anyway").textContent = sum(ANYWAY);

  const list = document.getElementById("recent");
  list.replaceChildren(...(history.filter((e) => e.action !== "noted").slice(0, 5).map((e) =>
    h("li", {},
      h("div", { class: "row" },
        h("span", { class: `tag ${actionTone(e.action)}` }, ACTION_LABELS[e.action] ?? e.action),
        h("span", {}, siteName(sites, e.site)),
        h("span", { class: "muted" }, when(e.at))),
      h("span", { class: "mono muted" }, e.findings.map((f) => f.masked_preview || f.rule_id).slice(0, 2).join(" · ") || e.kind)))));
  if (!list.children.length) list.append(h("li", { class: "empty muted" }, "Nothing stopped yet. Shadow Lens checks quietly in the background."));

  const companion = document.getElementById("companion");
  if (policy.companion) {
    ask("companionStatus").then((s) => {
      companion.replaceChildren(s.connected
        ? h("a", { href: s.info?.dashboard ?? "http://127.0.0.1:8787/", target: "_blank" }, "Open the dashboard")
        : h("span", { title: s.error ?? "" }, "Dashboard not installed"));
    }).catch(() => {});
  }
}

document.getElementById("open-options").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

document.getElementById("build").textContent = `Version ${chrome.runtime.getManifest().version_name ?? chrome.runtime.getManifest().version}`;
render();

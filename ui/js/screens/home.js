// Home (Frontend Design PDF p4 ON, p5 OFF, p6 turn-off dialog).
// The master switch maps to POST /api/capture/start and /stop: the design's switch has no API of its own yet (UD-01).
// Turning on has no confirmation because none is drawn (UD-02). Loading and error states follow p9 (UD-03).
import { el, fmtNumber, fmtTime, bandLabel, pct, bandTone } from "../ui.js";
import { openModal } from "../components/modal.js";
import { watch, load, byNewest, cardError, alertHref } from "./util.js";

const TOPICS = ["summary", "alerts", "capture", "sources"];

export function mount(container, ctx) {
  const { store, api, primitives: P, toasts } = ctx;
  let offAt = null;         // when this window saw protection turn off; the API has no field for it yet
  let busy = false;
  const root = el("div", { class: "home" });
  container.append(root);

  const isOn = (cap) => !!cap && cap.mode !== "idle";

  async function setProtection(on) {
    busy = true; render();
    try {
      const cap = await api.post(on ? "/api/capture/start" : "/api/capture/stop", on ? { scan: true, tail: true } : {});
      offAt = on ? null : new Date().toISOString();
      store.patch("capture", () => cap);
    } catch (err) {
      toasts.error(`Could not turn protection ${on ? "on" : "off"}.`, err.message, () => setProtection(on));
    } finally {
      busy = false; render();
    }
  }

  function askTurnOff() {
    openModal({
      label: "Turn protection off?",
      title: "ShadowLens will stop watching.",
      body: "Sources and the live scan stop, and the guard stops checking prompts. Nothing new is seen until you turn protection back on. Findings already stored stay.",
      confirmLabel: "Turn off",
      cancelLabel: "Keep on",
      onConfirm: () => setProtection(false),
    });
  }

  /* ---------- hero ---------- */
  function hero(cap, sourcesCount) {
    const capEntry = store.state("capture");
    if (!cap) {
      const inner = capEntry.status === "error"
        ? P.errorBlock({ message: `Could not read the protection status. ${capEntry.error.message}`, onRetry: () => store.refresh("capture") })
        : el("div", { class: "loading-text loading-text--night", role: "status" }, "Loading the protection status…");
      return el("section", { class: "card card--night hero" }, el("div", { class: "label hero__label" }, "ShadowLens protection"), inner);
    }
    const on = isOn(cap);
    const sw = el("button", {
      class: `master${on ? " master--on" : ""}`, type: "button", role: "switch", id: "master-switch",
      "aria-checked": String(on), "aria-label": "ShadowLens protection", disabled: busy,
      onClick: () => (on ? askTurnOff() : setProtection(true)),
    }, el("span", { class: "master__text", "aria-hidden": "true" }, on ? "ON" : "OFF"), el("span", { class: "master__knob", "aria-hidden": "true" }));

    let meta;
    if (on) {
      const since = cap.since ? `On since ${fmtTime(cap.since)} · ${Math.max(0, Math.round((Date.now() - new Date(cap.since)) / 60000))} min` : "On";
      meta = el("div", { class: "hero__meta" }, since);
    } else {
      const when = offAt ?? cap.stopped_at;
      meta = el("div", { class: "hero__meta" },
        el("span", {}, when ? `Turned off at ${fmtTime(when)} · last good data shown below` : "Last good data shown below"),
        P.button({ label: "Turn on protection", disabled: busy, onClick: () => setProtection(true) }));
    }
    return el("section", { class: `card card--night hero${on ? "" : " hero--off"}`, "aria-labelledby": "hero-title" },
      el("a", { class: "monolink hero__pitch", href: "#/pitch" }, "See the pitch →"),
      el("div", { class: "label hero__label" }, "ShadowLens protection"),
      el("div", { class: `master__ring${on ? " master__ring--on" : ""}` }, sw),
      el("h1", { class: "hero__title", id: "hero-title" }, on ? "Protection is ON" : "Protection is OFF"),
      el("p", { class: "hero__text" }, on
        ? `ShadowLens is watching ${sourcesCount} source${sourcesCount === 1 ? "" : "s"} and the guard is checking prompts before they reach AI tools.`
        : "ShadowLens is not watching. New activity is not being seen, and the guard is not checking prompts."),
      meta);
  }

  /* ---------- cards ---------- */
  function summaryCard(summary, alerts, cap, on) {
    const rows = [
      ["Events checked", summary.totals.events],
      ["Findings", summary.totals.findings],
      ["Alerts raised", alerts?.total ?? summary.totals.alerts_open],
      ["AI triage calls blocked", summary.llm.blocked],
    ];
    const sub = on ? (cap?.since ? `Since ${fmtTime(cap.since).slice(0, 5)}` : "This session") : "Last session, now paused";
    return el("section", { class: "card card--tint home-card" },
      el("h2", { class: "label" }, "Protection summary"),
      el("div", { class: "home-card__sub" }, sub),
      el("dl", { class: "kv" }, ...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, fmtNumber(v))])));
  }

  function monitorRows(cap, sources, on) {
    // The live log folder row comes from capture status below, and unsupported sources are not shown.
    const rows = (sources?.items ?? []).filter((s) => s.kind !== "live_log" && s.supported !== false).map((s) => ({ name: s.name, active: on && s.enabled, detail: on ? (s.enabled ? s.detail : "off") : (s.enabled ? "paused" : "off") }));
    if (cap) {
      rows.push({ name: "Live scan", active: on && cap.scan.enabled, detail: on && cap.scan.enabled ? `every ${cap.scan.interval_s} s` : "off" });
      rows.push({ name: "Live log folder", active: on && cap.live_tail.enabled, detail: on && cap.live_tail.enabled ? `${fmtNumber(cap.live_tail.lines_ingested)} lines` : "off" });
    }
    return rows;
  }

  function monitorCard(summary, rows, on) {
    const c = summary.coverage;
    const total = c.full + c.metadata_only;
    const band = on
      ? P.coverageBand({ full: c.full, metadataOnly: c.metadata_only })
      : el("div", { class: "coverage", role: "img", "aria-label": "Seen right now 0 percent, not seen 100 percent" },
          el("div", { class: "coverage__bar" }, el("div", { class: "coverage__unseen" })),
          el("div", { class: "coverage__nums" }, el("span", {}, "seen right now 0%"), el("span", {}, "not seen 100%")));
    const srcState = store.state("sources");
    // A 404 means this backend has no /api/sources: nothing to report. Other failures are real errors.
    const srcErr = srcState.status === "error" && !store.get("sources") && srcState.error?.status !== 404;
    return el("section", { class: "card home-card" },
      el("h2", { class: "label" }, "Active monitoring"),
      el("ul", { class: "monitor" }, ...rows.map((r) =>
        el("li", { class: `monitor__row${r.active ? " is-on" : ""}` },
          el("span", { class: "monitor__mark", "aria-hidden": "true" }),
          el("span", { class: "monitor__name" }, r.name, el("span", { class: "visually-hidden" }, r.active ? ", on" : ", off")),
          el("span", { class: "monitor__detail" }, r.detail)))),
      srcErr ? el("p", { class: "small" }, "Transcript and tap sources could not be read.") : null,
      total || !on ? el("div", { class: "home-card__foot" }, band) : null);
  }

  function riskCard(summary, on) {
    const r = summary.risk;
    return el("section", { class: `card card--night home-card risk${on ? "" : " risk--off"}` },
      el("h2", { class: "label" }, "Current risk level"),
      el("div", { class: "risk__line" }, el("span", { class: `risk__num ${bandTone(r.band)}` }, String(r.org_risk)), el("span", { class: `risk__band ${bandTone(r.band)}` }, bandLabel(r.band))),
      el("p", { class: "risk__text" }, on
        ? `Updating live. Compliance score ${r.compliance_score}.`
        : `Last known${offAt ? ` at ${fmtTime(offAt)}` : ""}. Not updating while protection is off.`),
      el("a", { class: "monolink", href: "#/overview" }, "Open Overview"));
  }

  function alertsCard(on) {
    const entry = store.state("alerts");
    let body;
    if (!entry.data && entry.status === "error") body = cardError(`Could not load alerts. ${entry.error.message}`, () => store.refresh("alerts"));
    else if (!entry.data) body = el("p", { class: "loading-text loading-text--small", role: "status" }, "Loading alerts…");
    else {
      const items = byNewest(entry.data.items).slice(0, 4);
      body = items.length
        ? el("ul", { class: "rlist" }, ...items.map((a) => el("li", {},
            el("a", { class: "rlist__row", href: alertHref(a.id) }, P.sevMark(a.severity),
              el("span", { class: "rlist__title" }, a.title), el("span", { class: "rlist__time" }, fmtTime(a.created_at))))))
        : el("p", { class: "small" }, "No alerts yet.");
    }
    return el("section", { class: "card home-card" },
      el("div", { class: "home-card__head" },
        el("h2", { class: "label" }, on ? "Recent alerts" : "Alerts before it was turned off"),
        el("a", { class: "monolink", href: "#/alerts" }, "View all")),
      body);
  }

  /* ---------- render ---------- */
  function render() {
    const hadFocus = document.activeElement?.id === "master-switch";
    const sEntry = store.state("summary");
    const summary = sEntry.data;
    const cap = store.get("capture");
    const on = isOn(cap);
    const rows = monitorRows(cap, store.get("sources"), on);
    const activeCount = rows.filter((r) => r.active).length;

    let lower;
    if (!summary && sEntry.status === "error") {
      lower = el("section", { class: "card home-state" }, P.errorBlock({ message: `Could not load the summary. ${sEntry.error.message}`, onRetry: () => store.refresh("summary") }));
    } else if (!summary) {
      lower = el("section", { class: "card home-state" }, P.loadingText("Loading the summary…"));
    } else {
      lower = el("div", { class: "home-grid" },
        summaryCard(summary, store.get("alerts"), cap, on || !cap),
        monitorCard(summary, rows, on || !cap),
        riskCard(summary, on || !cap),
        alertsCard(on || !cap));
    }
    root.replaceChildren(hero(cap, activeCount), lower);
    if (hadFocus) document.getElementById("master-switch")?.focus();
  }

  const off = watch(store, TOPICS, render);
  render();
  load(store, TOPICS);
  const tick = setInterval(render, 60000);     // keeps "On since … min" current
  return () => { off(); clearInterval(tick); };
}

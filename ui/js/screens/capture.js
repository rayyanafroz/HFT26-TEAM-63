// Capture (Frontend Design PDF p16 visibility, p17 controls, p18 sources). Three views under one nav link: ?view=visibility|controls|sources.
// Sources (P1) uses /api/sources, which is not in SOT 6.7 yet: list GET /api/sources, switch PUT /api/sources/{id} {enabled},
// "Scan existing history" POST /api/sources/{id}/scan. These paths are proposals until the backend confirms them.
import { el, fmtNumber, fmtTime, pct } from "../ui.js";
import { watch, load } from "./util.js";

const VIEWS = [{ id: "visibility", label: "Visibility" }, { id: "controls", label: "Controls" }, { id: "sources", label: "Sources" }];
const SUBTITLE = { visibility: "What ShadowLens watches, and what it cannot see.", controls: "Controls, scenarios and the last ingest.", sources: "One card per source. Switch it on to start watching." };
const PLATFORM = { linux: "Linux", darwin: "macOS", windows: "Windows" };
const SCOPE = { own_user: "own user", all_users: "all users", unknown: "unknown" };
const MAX_LOG_BYTES = 20 * 1024 * 1024;
const SCENARIOS = ["full_demo"];

export function mount(container, ctx) {
  const { store, api, primitives: P, toasts, runScenario } = ctx;
  let view = VIEWS.some((v) => v.id === ctx.params.view) ? ctx.params.view : "visibility";
  let busy = null;
  let scenario = SCENARIOS[0];

  const sub = el("p", { class: "small" });
  const seg = P.segmented({ items: VIEWS, selected: view, onSelect: (id) => { location.hash = `#/capture?view=${id}`; } });
  const body = el("div", {});
  container.append(el("header", { class: "screen-head screen-head--row" },
    el("div", {}, el("h1", { class: "h2" }, "Capture"), sub), seg), body);

  const stateOf = (topic, what) => {
    const e = store.state(topic);
    // The backend does not serve this endpoint yet: say so plainly, with no Retry (retrying cannot help).
    if (!e.data && e.status === "error" && (e.error.status === 404 || e.error.status === 405)) return P.emptyBlock({ message: `The local service does not provide ${what} yet.` });
    if (!e.data && e.status === "error") return P.errorBlock({ message: `Could not read ${what}. ${e.error.message}`, onRetry: () => store.refresh(topic) });
    if (!e.data) return P.loadingText(`Loading ${what}…`);
    return null;
  };

  /* ---------- p16 visibility ---------- */
  function visibilityView() {
    const s = store.get("summary");
    const v = store.get("visibility");
    const covCard = el("section", { class: "card cap-cov" }, el("h2", { class: "label" }, "Coverage"));
    if (!s) covCard.append(stateOf("summary", "the coverage"));
    else {
      const c = s.coverage;
      covCard.append(
        el("div", { class: "cap-cov__big" }, `${fmtNumber(c.full)} full · ${fmtNumber(c.metadata_only)} metadata only`),
        P.coverageBand({ full: c.full, metadataOnly: c.metadata_only }),
        el("p", { class: "cap-cov__text" }, v?.statement ?? "Payload inspection only applies to events with full visibility. HTTPS traffic is reported as metadata only."));
    }
    const visCard = el("section", { class: "card cap-vis" }, el("h2", { class: "label cap-vis__label" }, "Visibility panel"));
    if (!v) visCard.append(el("div", { class: "lab__pad" }, stateOf("visibility", "the visibility table")));
    else visCard.append(el("div", { class: "table-scroll" }, el("table", { class: "table cap-table" },
      el("thead", {}, el("tr", {}, ...["Source", "Can see", "Cannot see", "Visibility"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, ...v.rows.map((r) => el("tr", {},
        el("th", { scope: "row" }, r.source), el("td", {}, r.can_see), el("td", {}, r.cannot_see),
        el("td", {}, P.stateCell(r.visibility === "full" ? "used" : "unseen", { label: r.visibility === "full" ? "full" : "metadata only" }))))))));

    return el("div", { class: "cap" }, el("div", { class: "cap-row cap-row--vis" }, covCard, visCard), statusCard());
  }

  function statusCard() {
    const cap = store.get("capture");
    const card = el("section", { class: "card" }, el("h2", { class: "label card__label" }, "Capture status"));
    if (!cap) { card.append(stateOf("capture", "the status")); return card; }
    const src = store.get("sources")?.items ?? [];
    const trans = src.filter((x) => x.kind === "transcripts" && x.enabled);
    const tap = src.find((x) => x.kind === "ollama_tap");
    const item = (k, v, strong, tone = "") => el("div", { class: "stat" }, el("div", { class: "label" }, k), el("div", { class: `${strong ? "stat__v is-strong" : "stat__v"} ${tone}` }, v));
    card.append(el("div", { class: "stat-grid" },
      item("Mode", cap.mode, true, cap.mode === "idle" ? "" : "tone-green"),
      item("Live scan", cap.scan.enabled ? `on · every ${cap.scan.interval_s} s` : "off"),
      item("Last scan", fmtTime(cap.scan.last_scan_at)),
      item("Scope", SCOPE[cap.scan.scope] ?? cap.scan.scope),
      item("Elevated rights", cap.scan.privileged ? "yes" : "no"),
      item("Platform", PLATFORM[cap.platform] ?? cap.platform),
      item("Live log folder", cap.live_tail.enabled ? `${cap.live_tail.dir} · ${fmtNumber(cap.live_tail.lines_ingested)} lines` : "off"),
      src.length ? item("Transcripts", trans.length ? `${trans.length} source${trans.length > 1 ? "s" : ""} · ${fmtNumber(trans.reduce((n, x) => n + (x.files_watched ?? 0), 0))} files · ${fmtNumber(trans.reduce((n, x) => n + (x.lines_read ?? 0), 0))} lines` : "off") : null,
      tap ? item("Ollama tap", tap.enabled ? `on · port ${tap.listen} → ${tap.upstream} · ${fmtNumber(tap.lines_read ?? 0)} requests` : "off") : null,
      tap ? item("Last tap error", tap.error ?? "none") : null));
    if (cap.scan.scope === "own_user" && !cap.scan.privileged) {
      card.append(el("p", { class: "small cap-note" }, "The scan sees only processes owned by your user. Run ShadowLens with elevated rights to see all users."));
    }
    if (!cap.scan.psutil_ok) card.append(el("p", { class: "small cap-note" }, "The connection scan is not available on this machine."));
    return card;
  }

  /* ---------- p17 controls ---------- */
  async function doAction(key, fn, failText) {
    busy = key; render();
    try { await fn(); } catch (err) { toasts.error(failText, err.message, () => doAction(key, fn, failText)); }
    finally { busy = null; render(); }
  }
  const ingested = (r, source) => {
    store.patch("ingest", () => ({ ...r, source: r.source ?? source, at: new Date().toISOString() }));
    toasts.info(`${r.accepted} events accepted`, `${r.findings} findings · ${r.alerts} alerts${r.skipped ? ` · ${r.skipped} skipped` : ""}`, "Ingest");
    ["summary", "alerts", "capture"].forEach((t) => store.refresh(t));
  };

  const fileInput = el("input", { type: "file", accept: ".jsonl,.har", class: "visually-hidden", id: "log-upload", tabindex: "-1" });
  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    fileInput.value = "";
    if (!file) return;
    if (!/\.(jsonl|har)$/i.test(file.name)) { toasts.error("Could not upload the log.", "Choose a .jsonl or .har file."); return; }
    if (file.size > MAX_LOG_BYTES) { toasts.error("Could not upload the log.", "The file is over 20 MB."); return; }
    doAction("upload", async () => ingested(await api.upload("/api/ingest/log", file), file.name), `Could not upload ${file.name}.`);
  });

  function controlsView() {
    const cap = store.get("capture");
    const manual = el("section", { class: "card" }, el("h2", { class: "label card__label" }, "Manual controls"),
      el("div", { class: "ctl-row" },
        P.button({ label: busy === "scan" ? "Scanning…" : "Scan now", disabled: !!busy,
          onClick: () => doAction("scan", async () => ingested(await api.post("/api/scan/connections"), "scan"), "Could not scan connections.") }),
        cap ? P.toggle({ checked: cap.scan.enabled, disabled: busy === "livescan", label: "Live scan", name: "live-scan",
          onChange: (on) => doAction("livescan", async () => { const c = await api.post(on ? "/api/capture/start" : "/api/capture/stop", { scan: true }); store.patch("capture", () => c); }, `Could not turn the live scan ${on ? "on" : "off"}.`) }) : null),
      el("div", { class: "ctl-row" },
        P.button({ label: busy === "upload" ? "Uploading…" : "Upload log (.jsonl, .har)", variant: "secondary", disabled: !!busy, onClick: () => fileInput.click() }),
        P.button({ label: "Upload PCAP", variant: "secondary", disabled: true, ariaLabel: "Upload PCAP, not available yet" })),
      el("p", { class: "small" }, "PCAP upload is not available yet."), fileInput);

    const sc = cap?.scenario;
    const playing = cap?.mode === "playing" || (sc && sc.total && sc.played < sc.total);
    const scen = el("section", { class: "card" }, el("h2", { class: "label card__label" }, "Scenarios"),
      el("div", { class: "ctl-row" },
        el("label", { class: "visually-hidden", for: "cap-scenario" }, "Scenario"),
        el("select", { class: "input cap-select", id: "cap-scenario", onChange: (e) => { scenario = e.target.value; } },
          ...SCENARIOS.map((n) => el("option", { value: n, selected: n === scenario }, n))),
        P.button({ label: "Load", variant: "secondary", onClick: () => runScenario("load", scenario) }),
        P.button({ label: "Play", onClick: () => runScenario("play", scenario) }),
        P.button({ label: "Stop", variant: "secondary", disabled: !playing, onClick: () => runScenario("stop", sc?.name ?? scenario) }),
        P.button({ label: "Reset", variant: "secondary", onClick: () => runScenario("reset") })));
    if (sc && sc.total) {
      const p = pct(sc.played, sc.total);
      scen.append(
        el("p", { class: "cap-progress__text" }, `${playing ? "Playing" : "Played"} · ${fmtNumber(sc.played)} of ${fmtNumber(sc.total)} events`),
        el("div", { class: "cap-progress", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": String(sc.total), "aria-valuenow": String(sc.played), "aria-label": `${sc.name} progress` },
          el("div", { class: "cap-progress__done", style: `width:${p}%` }), el("div", { class: "cap-progress__left hatch" })),
        el("p", { class: "small" }, "Solid is played. Hatch is still to come."));
    } else {
      scen.append(el("p", { class: "small cap-progress__text" }, "No scenario is playing."));
    }

    const ing = store.get("ingest");
    const last = el("section", { class: "card" }, el("h2", { class: "label card__label" }, "Last ingest result"));
    if (!ing) last.append(el("div", { class: "empty-line" },
      el("p", {}, "No data yet. Load a scenario, upload a log, or enable a source."),
      el("div", { class: "ctl-row" },
        P.button({ label: "Load a scenario", variant: "small", onClick: () => runScenario("load", scenario) }),
        P.button({ label: "Upload a log", variant: "small", onClick: () => fileInput.click() }))));
    else {
      const n = (k, v) => el("div", { class: "stat" }, el("div", { class: "label" }, k), el("div", { class: "stat__big" }, fmtNumber(v)));
      last.append(el("div", { class: "ingest" }, n("Accepted", ing.accepted), n("Skipped", ing.skipped), n("Dropped, not AI", ing.dropped_non_ai), n("Findings", ing.findings), n("Alerts", ing.alerts)));
      if (ing.errors?.length) last.append(el("div", { class: "ingest__errors" }, el("h3", { class: "label" }, "First errors"),
        el("ul", { class: "mono tone-amber" }, ...ing.errors.slice(0, 20).map((e) => el("li", {}, e)))));
      else last.append(el("p", { class: "small ingest__ok" }, `${ing.source ?? "Ingest"}${ing.at ? ` at ${fmtTime(ing.at)}` : ""}. No errors.`));
    }
    return el("div", { class: "cap" }, el("div", { class: "cap-row cap-row--ctl" }, manual, scen), last);
  }

  /* ---------- p18 sources ---------- */
  function sourcesView() {
    const e = store.state("sources");
    if (!e.data) return el("section", { class: "card ov-state" }, stateOf("sources", "the sources"));
    if (!e.data.items.length) return el("section", { class: "card ov-state" }, P.emptyBlock({ message: "No sources are set up." }));
    return el("div", { class: "src-grid" }, ...e.data.items.map(sourceCard));
  }

  function sourceCard(s) {
    const unsupported = s.supported === false;
    const toggleId = `src-${s.id}`;
    const sw = P.toggle({ checked: !!s.enabled, disabled: unsupported || busy === toggleId, name: toggleId,
      onChange: (on) => doAction(toggleId, async () => {
        const r = await api.put(`/api/sources/${encodeURIComponent(s.id)}`, { enabled: on });
        store.patch("sources", (old) => old && { ...old, items: old.items.map((x) => (x.id === s.id ? { ...x, ...(r?.id === s.id ? r : {}), enabled: on } : x)) });
      }, `Could not turn ${s.name} ${on ? "on" : "off"}.`) });
    sw.querySelector("input").setAttribute("aria-label", `${s.name} ${s.enabled ? "on" : "off"}`);
    const where = s.kind === "ollama_tap" ? `listen ${s.listen} → upstream ${s.upstream}` : s.path ?? "";
    const kv = (k, v) => [el("dt", {}, k), el("dd", { class: "mono" }, v)];
    const card = el("section", { class: "card src" },
      el("div", { class: "src__head" }, el("h2", { class: "src__name" }, s.name), sw),
      where ? el("div", { class: "src__where" }, where) : null,
      el("div", { class: `src__found ${s.found ? "is-ok" : ""}` }, P.stateCell(s.found ? "used" : "granted", { label: s.found ? "found" : "not found" })),
      el("dl", { class: "pkv src__kv" },
        ...kv("Files watched", s.kind === "ollama_tap" ? "n/a" : fmtNumber(s.files_watched ?? 0)),
        ...kv("Lines read", fmtNumber(s.lines_read ?? 0)),
        ...kv("Last event", fmtTime(s.last_event_at))),
      el("p", { class: "src__line" }, el("strong", {}, "Reads: "), s.reads ?? "Nothing yet."),
      el("p", { class: "src__line" }, el("strong", {}, "Stores: "), s.stores ?? "Only masked findings."));
    if (s.error || unsupported) card.append(el("div", { class: "error-box src__err", role: "alert" }, s.error ?? "Not supported on this platform."));
    else if (s.kind === "transcripts") card.append(P.button({ label: busy === `hist-${s.id}` ? "Scanning…" : "Scan existing history", variant: "small", disabled: !!busy,
      onClick: () => doAction(`hist-${s.id}`, async () => ingested(await api.post(`/api/sources/${encodeURIComponent(s.id)}/scan`), s.name), `Could not scan ${s.name}.`) }));
    else if (s.kind === "ollama_tap" && s.listen) {
      const url = `http://127.0.0.1:${s.listen}`;
      const copyBtn = el("button", { class: "src__copy", type: "button" }, "Copy");
      copyBtn.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(url); copyBtn.textContent = "Copied"; }
        catch { copyBtn.textContent = "Select and copy"; }
        setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
      });
      card.append(el("div", { class: "src__point" }, el("span", {}, `Point the client at ${url}`), copyBtn));
    }
    return card;
  }

  /* ---------- wiring ---------- */
  function render() {
    sub.textContent = SUBTITLE[view];
    const focusId = document.activeElement?.id || document.activeElement?.name;
    body.replaceChildren(view === "controls" ? controlsView() : view === "sources" ? sourcesView() : visibilityView());
    if (focusId) (document.getElementById(focusId) ?? body.querySelector(`[name="${focusId}"]`))?.focus();
  }
  const off = watch(store, ["summary", "visibility", "capture", "sources", "ingest"], render);
  render();
  load(store, ["summary", "visibility", "capture", "sources"]);
  return {
    update(params) {
      const next = VIEWS.some((v) => v.id === params.view) ? params.view : "visibility";
      if (next !== view) { view = next; seg.querySelectorAll(".chip").forEach((c, i) => c.setAttribute("aria-pressed", String(VIEWS[i].id === view))); render(); }
    },
    unmount: off,
  };
}

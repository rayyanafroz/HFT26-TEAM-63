// App entry. Builds the shell, starts the router and the live connection.
import { el } from "./ui.js";
import { api, MOCK } from "./api.js";
import { store, TOPICS } from "./store.js";
import { live } from "./live.js";
import { ROUTES, createRouter } from "./router.js";
import * as primitives from "./components/primitives.js";
import { globalBar, statusStrip } from "./components/shell.js";
import { mountToastHost, toasts } from "./toasts.js";
import { showSplash } from "./splash.js";
import { tweenNumber } from "./motion.js";

showSplash();

const SCENARIOS = ["full_demo", "quick_leak", "agent_attack", "clean_baseline"];   // the four names the backend accepts (scenarios/loader.py); the design does not draw the list (UD-19)

const app = document.getElementById("app");
const banner = el("div", { hidden: true });
const main = el("main", { class: "main", id: "main", tabindex: "-1" });

/* Scenario actions. Errors say what failed and offer Retry. Reset has no confirmation because none is drawn (UD-20). */
async function runScenario(kind, name) {
  bar.setBusy(true);
  try {
    if (kind === "load") {
      const r = await api.post("/api/demo/load-scenario", { name });
      store.patch("ingest", () => ({ ...r, at: new Date().toISOString() }));
      toasts.info(`${name} loaded · ${r.accepted} events ready to play`);
    } else if (kind === "play") {
      const r = await api.post("/api/demo/play", { name });
      toasts.info(`${name} playing`, `${r.total} events over ${Math.round(r.duration_s)} s`);
    } else if (kind === "stop") {
      await api.post("/api/demo/stop");
      toasts.info(`${name} stopped`);
    } else {
      await api.post("/api/demo/reset");
      toasts.info("Reset", "All data cleared.");
    }
    // Re-read every topic that a screen has loaded, so all screens show the new data.
    for (const topic of Object.keys(TOPICS)) if (store.state(topic).status !== "idle") store.refresh(topic);
  } catch (err) {
    toasts.error(`Could not ${kind} ${kind === "reset" ? "the data" : name}.`, err.message, () => runScenario(kind, name));
  } finally {
    bar.setBusy(false);
  }
}

const bar = globalBar({
  routes: ROUTES, scenarios: SCENARIOS,
  onLoad: (n) => runScenario("load", n), onPlay: (n) => runScenario("play", n), onReset: () => runScenario("reset"),
});
const strip = statusStrip();
app.append(bar.node, strip.node, main);
main.before(banner);
mountToastHost();

function paintStrip() {
  const cap = store.get("capture");
  strip.update({ health: store.get("health"), summary: store.get("summary"), conn: live.state, illustrative: MOCK, protectionOn: cap ? cap.mode !== "idle" : true });
  const reconnecting = live.state === "reconnecting";
  banner.hidden = !reconnecting;
  if (reconnecting) {
    banner.replaceChildren(primitives.banner("Live stream dropped. Polling every 3 s. Reconnecting.", { right: "connection: reconnecting" }));
    banner.style.padding = "24px 24px 0";
  }
}
store.subscribe("summary", paintStrip);

// When the org risk changes, count the visible risk numbers from the old value to the new one.
let lastRisk = null;
store.subscribe("summary", (entry) => {
  const next = entry.data?.risk?.org_risk;
  if (next == null) return;
  const prev = lastRisk;
  lastRisk = next;
  if (prev == null || prev === next) return;
  requestAnimationFrame(() => document.querySelectorAll(".risk__num, .cmp-risk__num").forEach((n) => tweenNumber(n, prev, next)));
});
store.subscribe("health", paintStrip);
store.subscribe("capture", paintStrip);
live.onState(paintStrip);

live.on("alert.new", (a) => { if (a.severity === "critical" || a.severity === "high") toasts.alert(a); });

const router = createRouter({
  container: main,
  ctx: { api, store, live, primitives, toasts, runScenario, errorBlock: primitives.errorBlock },
  onRoute: (route) => bar.setActive(route.navAs ?? route.id),
});

paintStrip();
store.refresh("health");
store.refresh("summary");
store.refresh("capture");
live.start();
router.render();

// Handy in the browser console and in the hosted preview.
window.shadowlens = { store, live, toasts };

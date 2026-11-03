import { leaveScreen, enterScreen } from "./motion.js";

// Hash router: #/home, #/alerts?alert=<id>. Screens are modules that export mount(container, ctx) -> unmount().
// Home is the default route. An unknown route goes to Home.

export const ROUTES = [
  { id: "home",      label: "Home", ready: true },
  { id: "overview",  label: "Overview", ready: true },
  { id: "alerts",    label: "Alerts", ready: true },
  { id: "lab",       label: "Leak Lab", ready: true },
  { id: "guard",     label: "Guard", ready: true },
  { id: "agents",    label: "Agents", ready: true },
  { id: "providers", label: "Providers", ready: true },
  { id: "capture",   label: "Capture", ready: true },
  { id: "compliance", label: "Compliance", ready: true },
];

// Routes that open from inside a screen and have no nav link. navAs keeps that nav link highlighted.
export const HIDDEN_ROUTES = [];

const LOADERS = {
  home: () => import("./screens/home.js"),
  overview: () => import("./screens/overview.js"),
  alerts: () => import("./screens/alerts.js"),
  lab: () => import("./screens/lab.js"),
  guard: () => import("./screens/guard.js"),
  agents: () => import("./screens/agents.js"),
  providers: () => import("./screens/providers.js"),
  capture: () => import("./screens/capture.js"),
  compliance: () => import("./screens/compliance.js"),
};
const loadScreen = (id) => (LOADERS[id] ?? LOADERS.home)();

export function parseHash(hash = window.location.hash) {
  const raw = hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const id = path.split("/")[0] || "home";
  return { id, params: Object.fromEntries(new URLSearchParams(query)) };
}

export function navigate(id, params) {
  const qs = params ? `?${new URLSearchParams(params)}` : "";
  window.location.hash = `#/${id}${qs}`;
}

/** createRouter({ container, ctx, onRoute(route) }) */
export function createRouter({ container, ctx, onRoute }) {
  let unmount = null;
  let update = null;        // screens may return { unmount, update(params) } to handle ?params without a remount
  let currentId = null;
  let stopEnter = null;
  let token = 0;

  async function render() {
    const { id, params } = parseHash();
    const route = [...ROUTES, ...HIDDEN_ROUTES].find((r) => r.id === id && r.ready);
    if (!route) { navigate("home"); return; }
    if (id === currentId && update) { update(params); return; }
    const mine = ++token;
    unmount?.();
    unmount = null; update = null; currentId = id;
    stopEnter?.();
    await leaveScreen(container);          // brief fade so pages do not swap abruptly
    if (mine !== token) return;
    container.replaceChildren();
    onRoute?.(route, params);
    document.title = `${route.label} · Shadow Lens`;
    try {
      const mod = await loadScreen(route.id);
      if (mine !== token) return;                              // another navigation won
      const result = mod.mount(container, { ...ctx, route, params });
      if (typeof result === "function") unmount = result;
      else if (result) { unmount = result.unmount ?? null; update = result.update ?? null; }
      stopEnter = enterScreen(container);
    } catch (err) {
      if (mine !== token) return;
      container.replaceChildren(ctx.errorBlock({ message: `Could not open ${route.label}. ${err.message}`, onRetry: render }));
      stopEnter = enterScreen(container);
    }
    container.focus({ preventScroll: true });
  }

  window.addEventListener("hashchange", render);
  return { render, stop: () => window.removeEventListener("hashchange", render) };
}

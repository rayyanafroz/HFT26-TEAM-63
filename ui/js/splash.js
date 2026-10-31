// Splash screen: the mark draws itself over a slow hatch field, then fades to the app.
// About 1.6 s; shorter and still with reduced motion. Shown once per browser session.
import { el } from "./ui.js";
import { logoMark } from "./components/primitives.js";

const KEY = "shadowlens.splash.seen";

export function showSplash() {
  let seen = false;
  try { seen = sessionStorage.getItem(KEY) === "1"; sessionStorage.setItem(KEY, "1"); } catch { /* storage blocked: show it */ }
  if (seen) return;

  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const mark = logoMark({ size: 120, night: true });
  mark.removeAttribute("role"); mark.removeAttribute("aria-label");
  const [half, ring, edge] = mark.children;
  half.classList.add("splash__half");
  ring.classList.add("splash__ring");
  ring.setAttribute("pathLength", "100");
  edge.classList.add("splash__edge");

  const node = el("div", { class: `splash${reduced ? " splash--still" : ""}`, "aria-hidden": "true" },
    el("div", { class: "splash__field" }),
    el("div", { class: "splash__glow" }),
    el("div", { class: "splash__center" }, mark, el("div", { class: "splash__word" }, "ShadowLens")));
  document.body.append(node);

  const hold = reduced ? 600 : 1400;
  setTimeout(() => node.classList.add("is-leaving"), hold);
  setTimeout(() => node.remove(), hold + 500);
}

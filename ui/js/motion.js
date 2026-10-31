// Motion helpers for the dashboard. GSAP when it has loaded, nothing otherwise, so screens never wait on animation.
// Reduced motion: no movement, only instant state changes.
import { loadGsap } from "./vendor.js";

let gsap = null;
export const ready = loadGsap().then((g) => { gsap = g; return g; }).catch(() => null);
export const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
const on = () => gsap && !reducedMotion();

/** Quick fade before a screen is replaced. Resolves when done (at most ~110 ms). */
export function leaveScreen(node) {
  if (!on() || !node.firstChild) return Promise.resolve();
  return new Promise((resolve) => gsap.to(node, { opacity: 0, y: -4, duration: 0.1, ease: "power1.in", onComplete: resolve }));
}

/** Fade the new screen in, then animate charts that appear in the first moments (data often arrives a beat later). */
export function enterScreen(node) {
  if (!on()) { if (gsap) gsap.set(node, { clearProps: "opacity,transform" }); return () => {}; }
  gsap.fromTo(node, { opacity: 0, y: 6 }, { opacity: 1, y: 0, duration: 0.22, ease: "power2.out", clearProps: "opacity,transform" });
  animateCharts(node);
  let raf = 0;
  const mo = new MutationObserver(() => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => animateCharts(node)); });
  mo.observe(node, { childList: true, subtree: true });
  const stop = setTimeout(() => mo.disconnect(), 1500);
  return () => { mo.disconnect(); clearTimeout(stop); cancelAnimationFrame(raf); };
}

const CHART_X = ".barlist__fill, .coverage__seen, .cap-progress__done";
const CHART_Y = ".tl__col";
function animateCharts(root) {
  if (!on()) return;
  const xs = [...root.querySelectorAll(CHART_X)].filter((n) => !n.dataset.in);
  const ys = [...root.querySelectorAll(CHART_Y)].filter((n) => !n.dataset.in);
  xs.forEach((n) => { n.dataset.in = "1"; });
  ys.forEach((n) => { n.dataset.in = "1"; });
  if (xs.length) gsap.from(xs, { scaleX: 0, transformOrigin: "0% 50%", duration: 0.6, ease: "power2.out", stagger: 0.03, clearProps: "transform" });
  if (ys.length) gsap.from(ys, { scaleY: 0, transformOrigin: "50% 100%", duration: 0.5, ease: "power2.out", stagger: 0.025, clearProps: "transform" });
}

/** Entrance for overlays: scrim fades, the box rises (modal) or slides (panel). */
export function overlayIn(scrim, box, from = { y: 12, scale: 0.985 }) {
  if (!on()) return;
  if (scrim) gsap.fromTo(scrim, { opacity: 0 }, { opacity: 1, duration: 0.18, ease: "power1.out" });
  gsap.fromTo(box, { opacity: 0, ...from }, { opacity: 1, x: 0, y: 0, scale: 1, duration: 0.24, ease: "power2.out", clearProps: "transform,opacity" });
}

/** Exit for overlays and toasts. Calls done() after the animation, or at once without motion. */
export function overlayOut(nodes, to, done) {
  if (!on()) { done(); return; }
  gsap.to(nodes, { opacity: 0, ...to, duration: 0.16, ease: "power1.in", onComplete: done });
}

/** Count a number from one value to another inside an element. */
export function tweenNumber(node, from, to) {
  if (!on() || from === to || from == null) return;
  const o = { v: from };
  gsap.to(o, { v: to, duration: 0.6, ease: "power2.out", onUpdate: () => { node.textContent = String(Math.round(o.v)); } });
}

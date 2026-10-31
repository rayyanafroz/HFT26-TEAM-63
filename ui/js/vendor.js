// Local copies of third-party motion libraries (ui/vendor/). Nothing loads from a CDN (AT-20: zero external requests).
// GSAP + ScrollTrigger load for every screen; three.js + Vanta FOG load only when the pitch hero asks for them.
const cache = new Map();

function loadScript(src) {
  if (!cache.has(src)) {
    cache.set(src, new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = new URL(src, document.baseURI).href;
      s.async = false;
      s.onload = () => resolve();
      s.onerror = () => { cache.delete(src); reject(new Error(`Could not load ${src}`)); };
      document.head.append(s);
    }));
  }
  return cache.get(src);
}

/** Resolves to window.gsap with ScrollTrigger registered. */
export async function loadGsap() {
  await loadScript("vendor/gsap.min.js");
  await loadScript("vendor/ScrollTrigger.min.js");
  window.gsap.registerPlugin(window.ScrollTrigger);
  return window.gsap;
}

/** Resolves to window.VANTA (FOG effect) on top of three.js r134. */
export async function loadVanta() {
  await loadScript("vendor/three.min.js");
  await loadScript("vendor/vanta.fog.min.js");
  return window.VANTA;
}

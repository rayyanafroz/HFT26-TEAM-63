// Turning placeholders back into real values, on this device only.
//
// When the AI answers with "[OPENAI_API_KEY_1]" (or the person's own sent message shows it), the
// placeholder is highlighted, and the person can copy the message, or any selection of it, with the real
// values put back. The values never enter the page: highlights use the CSS Custom Highlight API (no change
// to the site's DOM), and the real text is fetched from the service worker only at the moment of copying.

import { PLACEHOLDER_RE } from "../shared/placeholders.js";

const HIGHLIGHT = "shadowlens-restorable";
const MAX_CHIPS = 12;

export function createRestore({ adapter, ui, send }) {
  let names = new Set();
  let timer = null;
  let observer = null;
  const highlight = typeof Highlight === "function" ? new Highlight() : null;
  if (highlight) CSS.highlights.set(HIGHLIGHT, highlight);
  const chips = new Map(); // message element -> chip element
  let marked = []; // [{ element, count }]

  async function refreshNames() {
    try {
      names = new Set((await send("vaultNames")).names);
    } catch {
      names = new Set();
    }
    schedule();
  }

  function messageOf(node) {
    for (const el of adapter.messages()) if (el.contains(node)) return el;
    return null;
  }

  function scanDocument() {
    highlight?.clear();
    marked = [];
    if (!names.size) return placeChips();
    const counts = new Map();
    const roots = adapter.messages();
    const walker = document.createTreeWalker(roots.length ? document.body : document.body, NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => (n.data.includes("[") && !n.parentElement?.closest("[contenteditable], textarea, script, style") ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT),
    });
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      for (const m of node.data.matchAll(PLACEHOLDER_RE)) {
        if (!names.has(m[0])) continue;
        if (highlight) {
          const range = new Range();
          range.setStart(node, m.index);
          range.setEnd(node, m.index + m[0].length);
          highlight.add(range);
        }
        const message = messageOf(node);
        if (message) counts.set(message, (counts.get(message) ?? 0) + 1);
      }
    }
    marked = [...counts].map(([element, count]) => ({ element, count }));
    placeChips();
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(scanDocument, 250);
  }

  async function copyMessage(element) {
    const shown = element.innerText;
    try {
      const { text } = await send("restore", { text: shown });
      await navigator.clipboard.writeText(text);
      ui.toast("Copied with the real values. They stay on this device.");
    } catch (error) {
      ui.toast(`Could not copy: ${error?.message ?? error}`);
    }
  }

  function placeChips() {
    const visible = marked
      .map((m) => ({ ...m, rect: m.element.getBoundingClientRect() }))
      .filter((m) => m.rect.bottom > 0 && m.rect.top < innerHeight && m.rect.width)
      .slice(0, MAX_CHIPS);
    const keep = new Set(visible.map((m) => m.element));
    for (const [element, chip] of chips) {
      if (!keep.has(element)) {
        chip.remove();
        chips.delete(element);
      }
    }
    for (const { element, count, rect } of visible) {
      let chip = chips.get(element);
      if (!chip) {
        chip = ui.h("div", { class: "chip", role: "group", "aria-label": "Shadow Lens" },
          ui.h("span"),
          ui.h("button", { type: "button", onclick: () => copyMessage(element) }, "Copy with real values"));
        ui.layer.append(chip);
        chips.set(element, chip);
      }
      chip.firstChild.textContent = `${count} hidden value${count === 1 ? "" : "s"}`;
      chip.style.left = `${Math.max(8, Math.min(rect.right - 260, innerWidth - 280))}px`;
      chip.style.top = `${Math.max(8, Math.min(rect.bottom - 4, innerHeight - 40))}px`;
    }
  }

  /** Ctrl+C on a selection that holds placeholders copies the real values instead. */
  function onCopy(e) {
    const selection = getSelection();
    const text = selection?.toString() ?? "";
    if (!names.size || !text.includes("[")) return;
    const found = [...text.matchAll(PLACEHOLDER_RE)].some((m) => names.has(m[0]));
    if (!found) return;
    const inside = selection.anchorNode && adapter.editableRoot(selection.anchorNode);
    if (inside) return; // copying out of the composer: leave placeholders (that text is going to the AI)
    e.preventDefault();
    e.clipboardData?.setData("text/plain", text); // placeholders at once; real values right after
    send("restore", { text })
      .then(({ text: restored }) => navigator.clipboard.writeText(restored))
      .then(() => ui.toast("Copied with the real values."))
      .catch(() => ui.toast("Copied with placeholders: the real values could not be added."));
  }

  function start() {
    observer = new MutationObserver(schedule);
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    addEventListener("copy", onCopy, true);
    addEventListener("scroll", placeChips, { passive: true, capture: true });
    addEventListener("resize", placeChips, { passive: true });
    refreshNames();
  }

  function stop() {
    observer?.disconnect();
    clearTimeout(timer);
    removeEventListener("copy", onCopy, true);
    removeEventListener("scroll", placeChips, { capture: true });
    removeEventListener("resize", placeChips);
    for (const chip of chips.values()) chip.remove();
    chips.clear();
    if (highlight) CSS.highlights.delete(HIGHLIGHT);
  }

  return { start, stop, refreshNames };
}

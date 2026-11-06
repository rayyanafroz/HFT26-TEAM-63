// Turning placeholders back into real values, on this device only.
//
// When the AI answers with "[OPENAI_API_KEY_1]" the placeholder is highlighted, and the person can copy the
// message or code block with the real values put back. The values never enter the page: highlights use the
// CSS Custom Highlight API (no change to the site's DOM), and the real text is fetched from the service
// worker only at the moment of copying.
//
// Real chat apps split text across many elements (a span per streamed word, a span per syntax token), so
// placeholders are found in the text of each block (paragraph, list item, code block...) as a whole and
// mapped back to ranges over the text nodes that hold them.

import { LOOSE_PLACEHOLDER_RE } from "../shared/placeholders.js";

const HIGHLIGHT = "shadowlens-restorable";
const MAX_CHIPS = 12;
const SCAN_EVERY_MS = 350;
const BLOCKS = new Set(["P", "LI", "PRE", "TD", "TH", "H1", "H2", "H3", "H4", "H5", "H6", "BLOCKQUOTE", "DD", "DT", "DIV", "SECTION", "ARTICLE", "FIGCAPTION", "SUMMARY", "BODY"]);
const SKIP = "[contenteditable], textarea, input, script, style, noscript, shadow-lens";

export function createRestore({ adapter, ui, send }) {
  let names = new Set(); // "[NAME_1]"
  let timer = null;
  let observer = null;
  const highlight = typeof Highlight === "function" ? new Highlight() : null;
  if (highlight) CSS.highlights.set(HIGHLIGHT, highlight);
  const chips = new Map(); // anchor element -> chip element
  let anchors = []; // [{ element, count }]

  async function refreshNames() {
    try {
      names = new Set((await send("vaultNames")).names);
    } catch {
      names = new Set();
    }
    scanNow();
  }

  function blockOf(node) {
    let el = node.parentElement;
    while (el && !BLOCKS.has(el.nodeName)) el = el.parentElement;
    return el ?? document.body;
  }

  /** The element a chip belongs to: the code block, else the message, else the block itself. */
  function anchorFor(block, node) {
    const pre = block.closest("pre") ?? node.parentElement?.closest("pre");
    if (pre) return pre;
    for (const message of adapter.messages()) if (message.contains(block)) return message;
    return block;
  }

  /** Text nodes grouped by their block, in document order. */
  function textBlocks() {
    const groups = new Map();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => (n.data && !n.parentElement?.closest(SKIP) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT),
    });
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const block = blockOf(node);
      if (!groups.has(block)) groups.set(block, []);
      groups.get(block).push(node);
    }
    return groups;
  }

  /** The (node, offset) holding character `at` of the joined text. `ends` are cumulative lengths. */
  function locate(nodes, ends, at, closing) {
    let lo = 0;
    let hi = nodes.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (ends[mid] < at || (!closing && ends[mid] === at)) lo = mid + 1;
      else hi = mid;
    }
    const start = lo === 0 ? 0 : ends[lo - 1];
    return [nodes[lo], at - start];
  }

  function scanNow() {
    clearTimeout(timer);
    timer = null;
    highlight?.clear();
    if (!names.size) {
      anchors = [];
      return placeChips();
    }
    const counts = new Map();
    for (const [block, nodes] of textBlocks()) {
      const joined = nodes.map((n) => n.data).join("");
      if (!/[A-Z][A-Z0-9_]*_\d/.test(joined)) continue;
      const ends = [];
      let sum = 0;
      for (const n of nodes) ends.push((sum += n.data.length));
      for (const m of joined.matchAll(LOOSE_PLACEHOLDER_RE)) {
        if (!names.has(`[${m[1]}]`)) continue;
        if (highlight) {
          const range = new Range();
          const [startNode, startOffset] = locate(nodes, ends, m.index, false);
          const [endNode, endOffset] = locate(nodes, ends, m.index + m[0].length, true);
          range.setStart(startNode, startOffset);
          range.setEnd(endNode, endOffset);
          highlight.add(range);
        }
        const anchor = anchorFor(block, nodes[0]);
        counts.set(anchor, (counts.get(anchor) ?? 0) + 1);
      }
    }
    // A message that holds code blocks gets chips on the blocks, not a second one over the whole message.
    anchors = [...counts].filter(([element]) => ![...counts.keys()].some((other) => other !== element && element.contains(other) && other.nodeName === "PRE"))
      .map(([element, count]) => ({ element, count }));
    placeChips();
  }

  /** Throttled, not debounced: a streaming reply changes the page continuously. */
  function schedule() {
    if (timer == null) timer = setTimeout(scanNow, SCAN_EVERY_MS);
  }

  async function copyFrom(element) {
    try {
      const { text } = await send("restore", { text: element.innerText });
      await navigator.clipboard.writeText(text);
      ui.toast("Copied with the real values. They stay on this device.");
    } catch (error) {
      ui.toast(`Could not copy: ${error?.message ?? error}`);
    }
  }

  function placeChips() {
    const visible = anchors
      .filter((a) => a.element.isConnected)
      .map((a) => ({ ...a, rect: a.element.getBoundingClientRect() }))
      .filter((a) => a.rect.bottom > 0 && a.rect.top < innerHeight && a.rect.width)
      .slice(0, MAX_CHIPS);
    const keep = new Set(visible.map((a) => a.element));
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
          ui.h("button", { type: "button", onclick: () => copyFrom(element) }, element.nodeName === "PRE" ? "Copy code with real values" : "Copy with real values"));
        ui.layer.append(chip);
        chips.set(element, chip);
      }
      chip.firstChild.textContent = `${count} hidden value${count === 1 ? "" : "s"}`;
      chip.style.left = `${Math.max(8, Math.min(rect.right - chip.offsetWidth - 8, innerWidth - chip.offsetWidth - 8))}px`;
      // On the top edge of the block (just above it when it fits, otherwise inside its top right).
      chip.style.top = `${Math.max(8, Math.min(rect.top > 40 ? rect.top - chip.offsetHeight - 4 : rect.top + 6, innerHeight - 40))}px`;
    }
  }

  /** Ctrl+C on a selection that holds placeholders copies the real values instead. */
  function onCopy(e) {
    const selection = getSelection();
    const text = selection?.toString() ?? "";
    if (!names.size || !selection?.rangeCount || !/[A-Z][A-Z0-9_]*_\d/.test(text)) return;
    const found = [...text.matchAll(LOOSE_PLACEHOLDER_RE)].some((m) => names.has(`[${m[1]}]`));
    if (!found) return;
    if (selection.anchorNode && adapter.editableRoot(selection.anchorNode)) return; // out of the composer: that text is going to the AI
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

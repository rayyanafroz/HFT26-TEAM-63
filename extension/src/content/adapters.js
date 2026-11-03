// What the guard needs to know about each site: where the person types, which control sends, and where
// the conversation is. Sites change their markup often, so each list holds several selectors, newest
// first, and the generic rules below catch what the lists miss.

const GENERIC_SEND = [
  'button[data-testid*="send" i]',
  'button[aria-label*="send" i]',
  'button[title*="send" i]',
  'button[aria-label*="submit" i]',
  'button[type="submit"]',
  // Many apps build their send control from a <div>.
  '[role="button"][aria-label*="send" i]',
  '[role="button"][data-testid*="send" i]',
];

const SEND_LABEL = /\bsend\b|\bsubmit\b/i;

function label(el) {
  return [el.getAttribute("aria-label"), el.getAttribute("title"), el.getAttribute("data-testid"), el.id].filter(Boolean).join(" ");
}

const PAGE_LEVEL = new Set(["MAIN", "BODY", "HTML"]);

/** Is `el` in the composer's own area: its form, or up to three levels around it, never the whole page? */
function near(el, editor) {
  if (!editor) return false;
  let scope = editor.closest("form") ?? editor;
  for (let i = 0; i < 3 && !scope.contains(el); i++) {
    const up = scope.parentElement;
    if (!up || PAGE_LEVEL.has(up.nodeName)) break;
    scope = up;
  }
  return scope.contains(el);
}

export const ADAPTERS = {
  chatgpt: {
    composer: ["#prompt-textarea", 'div.ProseMirror[contenteditable="true"]', 'textarea[name="prompt-textarea"]', "textarea#mobile-composer-prompt", 'form textarea[placeholder*="ChatGPT" i]'],
    send: ['button[data-testid="send-button"]', "#composer-submit-button", 'button[aria-label="Send prompt"]', 'button[aria-label="Send message"]', 'button[aria-label*="Send" i]'],
    messages: ["[data-message-author-role]"],
  },
  claude: {
    composer: ['div.ProseMirror[contenteditable="true"]', 'fieldset div[contenteditable="true"]', '[data-testid="chat-input"] [contenteditable="true"]'],
    send: ['button[aria-label="Send message"]', 'button[aria-label="Send Message"]', 'button[data-testid="send-button"]'],
    messages: ['[data-testid="user-message"]', ".font-claude-response", ".font-claude-message", "[data-is-streaming]"],
  },
  gemini: {
    composer: ['rich-textarea .ql-editor[contenteditable="true"]', 'div.ql-editor[contenteditable="true"]', 'rich-textarea [contenteditable="true"]'],
    send: ["button.send-button", 'button[aria-label="Send message"]', 'button[aria-label*="Send" i]'],
    messages: ["user-query", "model-response", "message-content"],
  },
  generic: {
    composer: ["textarea", '[contenteditable="true"]', '[contenteditable=""]'],
    send: [],
    messages: ["main article", "main [class*=message i]", "main"],
  },
};

const EDITABLE = 'textarea, [contenteditable="true"], [contenteditable=""], [contenteditable="plaintext-only"], input[type="text"], input[type="search"], input:not([type])';

export function createAdapter(id) {
  const spec = ADAPTERS[id] ?? ADAPTERS.generic;
  const sendSelectors = [...spec.send, ...GENERIC_SEND];

  /** The editable root that contains `node` (the whole editor, not an inner paragraph), or null. */
  function editableRoot(node) {
    const el = node?.nodeType === Node.ELEMENT_NODE ? node : node?.parentElement;
    let root = el?.closest?.(EDITABLE);
    if (!root) return null;
    if (root.isContentEditable) {
      while (root.parentElement?.isContentEditable) root = root.parentElement;
    }
    return root;
  }

  function isVisible(el) {
    return el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
  }

  /** A send control in the composer's own area (its form, or a few levels around it). */
  function sendNear(editor) {
    let scope = editor.closest("form") ?? editor;
    for (let i = 0; i < 5; i++) {
      for (const button of scope.querySelectorAll('button, [role="button"], input[type="submit"]')) {
        if (button !== editor && isVisible(button) && (sendSelectors.some((s) => button.matches(s)) || SEND_LABEL.test(label(button)))) return button;
      }
      const up = scope.parentElement;
      if (!up || PAGE_LEVEL.has(up.nodeName)) break;
      scope = up;
    }
    return null;
  }

  const CHAT_PLACEHOLDER = /ask|message|prompt|chat|type|anything|question|reply|search|write|talk/i;

  /**
   * Sites change their markup often (logged-out ChatGPT uses a plain <textarea>, for one), so besides
   * the site's own selectors, a visible multi-line editor counts as the composer when a send control is
   * near it or it is labelled like one ("Ask anything", "Message ChatGPT").
   */
  function looksLikeComposer(el) {
    if (!el || el instanceof HTMLInputElement || !(el instanceof HTMLTextAreaElement || el.isContentEditable)) return false;
    if (!isVisible(el)) return false;
    const hint = [el.getAttribute("placeholder"), el.getAttribute("aria-label"), el.getAttribute("data-placeholder"), el.closest("[aria-label]")?.getAttribute("aria-label")].filter(Boolean).join(" ");
    return !!sendNear(el) || CHAT_PLACEHOLDER.test(hint) || el.getBoundingClientRect().width >= 280;
  }

  let lastComposer = null;

  function isComposer(el) {
    if (!el) return false;
    const yes = spec.composer.some((s) => el.matches(s)) || looksLikeComposer(el);
    if (yes) lastComposer = el;
    return yes;
  }

  /** The main composer on the page: the site's own selectors, else the focused or last-used one, else the largest likely one. */
  function composer() {
    for (const s of spec.composer) {
      for (const el of document.querySelectorAll(s)) {
        const root = editableRoot(el);
        if (root && isVisible(root)) return root;
      }
    }
    const focused = editableRoot(document.activeElement);
    if (focused && looksLikeComposer(focused)) return focused;
    if (lastComposer?.isConnected && isVisible(lastComposer)) return lastComposer;
    let best = null;
    let bestArea = 0;
    for (const el of document.querySelectorAll('textarea, [contenteditable="true"], [contenteditable=""], [contenteditable="plaintext-only"]')) {
      const root = editableRoot(el);
      if (!root || !looksLikeComposer(root)) continue;
      const r = root.getBoundingClientRect();
      if (r.width * Math.max(r.height, 20) > bestArea) {
        best = root;
        bestArea = r.width * Math.max(r.height, 20);
      }
    }
    return best;
  }

  /** Is `node` (or an ancestor) the control that sends what is in `editor`? */
  function sendControl(node, editor) {
    const el = node?.nodeType === Node.ELEMENT_NODE ? node : node?.parentElement;
    const button = el?.closest?.('button, [role="button"], input[type="submit"]');
    if (!button) return null;
    if (spec.send.some((s) => button.matches(s))) return button;
    if (editor && sendNear(editor) === button) return button;
    // Otherwise only a control near the composer counts, so "Send feedback" elsewhere is left alone.
    if (!near(button, editor)) return null;
    if (GENERIC_SEND.some((s) => button.matches(s)) || SEND_LABEL.test(label(button))) return button;
    return null;
  }

  /** The send control for `editor`: inside its form first, then anywhere on the page. */
  function findSend(editor) {
    const near = editor && sendNear(editor);
    if (near) return near;
    const scopes = [editor?.closest("form"), editor?.parentElement?.parentElement?.parentElement, document].filter(Boolean);
    for (const scope of scopes) {
      for (const s of sendSelectors) {
        for (const button of scope.querySelectorAll(s)) {
          if (isVisible(button)) return button;
        }
      }
    }
    return null;
  }

  /** Elements that hold one message of the conversation. */
  function messages() {
    for (const s of spec.messages) {
      const found = document.querySelectorAll(s);
      if (found.length) return [...found];
    }
    return [];
  }

  return { id, editableRoot, isComposer, composer, sendControl, findSend, messages };
}

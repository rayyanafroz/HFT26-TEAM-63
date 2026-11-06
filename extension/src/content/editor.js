// Reading and rewriting what is in a composer: a <textarea>, or a rich editor (ProseMirror on ChatGPT and
// Claude, Quill on Gemini). Rich editors keep their own model of the text, so the DOM is never edited
// directly: text goes in the way a person would put it there (a paste, then typing), and every rewrite is
// read back to check it took.

const BLOCKS = new Set(["P", "DIV", "LI", "PRE", "H1", "H2", "H3", "H4", "H5", "H6", "BLOCKQUOTE", "TR"]);
const CONTAINERS = new Set(["UL", "OL", "TABLE", "TBODY", "THEAD"]);

let writing = false;

/** True while the guard itself is putting text into an editor (its own events must pass). */
export function isWriting() {
  return writing;
}

function isTextField(el) {
  return el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement;
}

/** Text of one block: <br> is a line break, except the editors' trailing placeholder <br>. */
function inlineText(node) {
  let out = "";
  for (const child of node.childNodes) {
    if (child.nodeType === Node.TEXT_NODE) out += child.data;
    else if (child.nodeName === "BR") {
      if (child !== node.lastChild) out += "\n"; // the last <br> of a block only holds an empty line open
    } else if (child.nodeType === Node.ELEMENT_NODE) {
      if (child.getAttribute("contenteditable") === "false" && !child.textContent.trim()) continue;
      out += BLOCKS.has(child.nodeName) || CONTAINERS.has(child.nodeName) ? blocksText(child) : inlineText(child);
    }
  }
  return out;
}

function blocksText(root) {
  const lines = [];
  let inline = "";
  const flush = () => {
    if (inline) lines.push(inline);
    inline = "";
  };
  for (const child of root.childNodes) {
    if (child.nodeType === Node.ELEMENT_NODE && (BLOCKS.has(child.nodeName) || CONTAINERS.has(child.nodeName))) {
      flush();
      lines.push(CONTAINERS.has(child.nodeName) ? blocksText(child) : inlineText(child));
    } else if (child.nodeType === Node.TEXT_NODE || child.nodeType === Node.ELEMENT_NODE) {
      inline += child.nodeType === Node.TEXT_NODE ? child.data : child.nodeName === "BR" ? "\n" : inlineText(child);
    }
  }
  flush();
  return lines.join("\n");
}

/** The text in an editor, one line per paragraph. */
export function readText(el) {
  if (!el) return "";
  if (isTextField(el)) return el.value;
  return blocksText(el);
}

function same(a, b) {
  const norm = (s) => s.replace(/\u00A0/g, " ").replace(/\s+$/, "");
  return norm(a) === norm(b);
}

/**
 * Wait until the editor has seen a selection we just set. ProseMirror and Quill copy the browser's
 * selection into their own model on "selectionchange", which fires after the current task; an edit sent
 * before that lands at the old cursor (a "replace all" would append instead).
 */
function selectionSettled() {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      document.removeEventListener("selectionchange", finish);
      setTimeout(resolve, 0); // after the editor's own selectionchange handler
    };
    document.addEventListener("selectionchange", finish);
    setTimeout(finish, 50);
  });
}

function selectAll(el) {
  el.focus();
  const range = document.createRange();
  range.selectNodeContents(el);
  const selection = getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

/** A paste event the editor will handle like a real one. */
export function dispatchPaste(target, data) {
  const transfer = new DataTransfer();
  for (const [type, value] of Object.entries(data.strings ?? {})) transfer.setData(type, value);
  for (const file of data.files ?? []) transfer.items.add(file);
  const event = new ClipboardEvent("paste", { clipboardData: transfer, bubbles: true, cancelable: true, composed: true });
  writing = true;
  try {
    target.dispatchEvent(event);
  } finally {
    writing = false;
  }
  return event.defaultPrevented;
}

function insertTextCommand(text) {
  writing = true;
  try {
    return document.execCommand("insertText", false, text);
  } finally {
    writing = false;
  }
}

function setFieldValue(el, value) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value); // React tracks the native setter
  writing = true;
  try {
    el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: value }));
  } finally {
    writing = false;
  }
}

/**
 * Replace everything in the editor with `text`. Tries a paste, then the browser's insertText command;
 * returns true only when reading the editor back gives `text`.
 */
export async function writeText(el, text) {
  if (isTextField(el)) {
    setFieldValue(el, text);
    return same(el.value, text);
  }
  const attempts = [
    async () => {
      selectAll(el);
      await selectionSettled();
      dispatchPaste(el, { strings: { "text/plain": text } });
    },
    async () => {
      selectAll(el);
      await selectionSettled();
      insertTextCommand(text);
    },
  ];
  for (const attempt of attempts) {
    await attempt();
    await new Promise((r) => requestAnimationFrame(() => r()));
    if (same(readText(el), text)) return true;
  }
  return false;
}

/** The current selection inside `el`, to put back after a panel took the focus. */
export function saveSelection(el) {
  if (isTextField(el)) return { start: el.selectionStart, end: el.selectionEnd };
  const selection = getSelection();
  if (!selection.rangeCount) return null;
  const range = selection.getRangeAt(0);
  return el.contains(range.startContainer) ? range.cloneRange() : null;
}

function restoreSelection(el, saved) {
  el.focus();
  if (!saved) return;
  if (isTextField(el)) {
    el.setSelectionRange(saved.start, saved.end);
    return;
  }
  const selection = getSelection();
  selection.removeAllRanges();
  selection.addRange(saved);
}

/**
 * Put pasted content where the person pasted it. `data` is what the clipboard held (all string types
 * and files) or a replacement text. Returns true when the text arrived in the editor.
 */
export async function insertAt(el, saved, data) {
  const plain = data.strings?.["text/plain"] ?? "";
  if (isTextField(el)) {
    restoreSelection(el, saved);
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? start;
    setFieldValue(el, el.value.slice(0, start) + plain + el.value.slice(end));
    el.setSelectionRange(start + plain.length, start + plain.length);
    return true;
  }
  const before = readText(el);
  restoreSelection(el, saved);
  await selectionSettled();
  dispatchPaste(el, data);
  await new Promise((r) => requestAnimationFrame(() => r()));
  const flat = (s) => s.replace(/\s+/g, "");
  if (!plain || (flat(readText(el)).includes(flat(plain)) && readText(el) !== before)) return true;
  restoreSelection(el, saved);
  await selectionSettled();
  insertTextCommand(plain);
  await new Promise((r) => requestAnimationFrame(() => r()));
  return flat(readText(el)).includes(flat(plain));
}

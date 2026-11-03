// The guard: checks text before it is pasted into an AI chat, before a message is sent, and before a file
// is uploaded, and lets it through, rewrites it, or asks the person.
//
// Events are caught in the capture phase on window, before the site's own handlers see them. A decision
// needs the engine (in the service worker), which answers asynchronously, so:
//
// * while the person types, the composer is checked in the background, and Enter on clean text passes
//   at once with no delay;
// * otherwise the event is stopped, the text is checked, and the guard re-sends, re-pastes or re-uploads
//   it itself when it may go. Its own re-sends are recognised by the exact text and a short time window.

import { clean } from "../shared/injection.js";
import { insertAt, isWriting, readText, saveSelection, writeText, dispatchPaste } from "./editor.js";
import { extractText, needsReader, toBase64 } from "./files.js";

const TYPING_DELAY_MS = 150;
const BYPASS_MS = 2500;
const CACHE_SIZE = 30;
const PASSES = new Set(["allow", "note"]);

const nextFrame = () => new Promise((r) => requestAnimationFrame(() => r()));

export function createGuard({ adapter, ui, send, site, config }) {
  let cfg = config;
  let bypass = null; // { text, until }: the guard's own re-send of this exact text
  let busy = false; // a decision is open; further sends wait for it
  let typingTimer = null;
  let typingEditor = null;
  let lastTyping = null; // { editor, result }
  const cache = new Map(); // text -> scan result
  const passThrough = new WeakSet(); // events the guard dispatched itself
  const listeners = [];

  const active = () => cfg.mode !== "off";

  function remember(text, result) {
    cache.delete(text);
    cache.set(text, result);
    if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
  }

  async function scan(text, kind) {
    const result = await send("scan", { text, kind, site: site.id });
    remember(text, result);
    return result;
  }

  function summary(result) {
    return result.findings.map(({ rule_id, hash12, masked_preview, severity }) => ({ rule_id, hash12, masked_preview, severity }));
  }

  function record(action, kind, result, extra = {}) {
    send("record", { event: { site: site.id, action, kind, severity: result?.decision?.severity ?? "none", findings: result ? summary(result) : [], ...extra } }).catch(() => {});
  }

  async function notASecret(finding) {
    try {
      await send("notASecret", { finding: { rule_id: finding.rule_id, hash12: finding.hash12, masked_preview: finding.masked_preview } });
      cache.clear();
      return true;
    } catch {
      return false;
    }
  }

  /** The panel for a failed check: the guard cannot vouch for the text, so the person decides. */
  function failure(mode, anchor, error) {
    return ui.decide({
      mode, anchor, findings: [], allowOverride: true, requireReason: false,
      decision: { action: "warn", severity: "none" },
      note: `Shadow Lens could not check this (${error?.message ?? "unknown error"}). Nothing has gone through.`,
    });
  }

  // ---------- typing ----------

  function onInput(e) {
    if (!active() || isWriting()) return;
    const editor = adapter.editableRoot(e.target);
    if (!editor) return;
    typingEditor = editor;
    clearTimeout(typingTimer);
    const text = readText(editor);
    typingTimer = setTimeout(() => checkTyping(editor), text.length > 100_000 ? 600 : TYPING_DELAY_MS);
  }

  async function checkTyping(editor) {
    const text = readText(editor);
    if (!text.trim()) {
      lastTyping = null;
      ui.setBadge(document.activeElement && editor.contains(document.activeElement) ? { anchor: editor, findings: [], action: "allow" } : null);
      return;
    }
    try {
      const result = cache.get(text) ?? (await scan(text, "typing"));
      if (readText(editor) !== text) return; // the person kept typing; a newer check is coming
      lastTyping = { editor, result };
      ui.setBadge({ anchor: editor, findings: result.findings, action: result.decision.action }, () => review(editor));
    } catch {
      /* the next keystroke will try again */
    }
  }

  function onFocusIn(e) {
    if (!active()) return;
    const editor = adapter.editableRoot(e.target);
    if (!editor) return;
    if (lastTyping?.editor === editor) ui.setBadge({ anchor: editor, findings: lastTyping.result.findings, action: lastTyping.result.decision.action }, () => review(editor));
    else checkTyping(editor);
  }

  /** The badge was clicked: show what was found, offer to redact in place. */
  async function review(editor) {
    const text = readText(editor);
    const result = cache.get(text) ?? (await scan(text, "typing"));
    const choice = await ui.decide({ mode: "info", findings: result.findings, decision: result.decision, anchor: editor, onNotASecret: notASecret });
    if (choice.choice === "redact_review") await redactInPlace(editor, text, result, "submit");
    if (choice.choice === "recheck") checkTyping(editor);
  }

  async function redactInPlace(editor, text, result, kind) {
    const redacted = await send("redact", { text, kind, site: site.id });
    const ok = await writeText(editor, redacted.text);
    if (!ok) {
      ui.toast("Shadow Lens could not rewrite the message here. Nothing was sent.");
      return null;
    }
    record("redacted", kind, result, { review: true });
    cache.delete(text);
    checkTyping(editor);
    return redacted;
  }

  // ---------- sending ----------

  function isSendKey(e) {
    return e.key === "Enter" && !e.shiftKey && !e.altKey && !e.isComposing && e.keyCode !== 229;
  }

  function onKeydown(e) {
    if (!active() || passThrough.has(e) || !isSendKey(e)) return;
    const editor = adapter.editableRoot(e.target);
    if (!editor || editor instanceof HTMLInputElement) return;
    if (!adapter.isComposer(editor) && !editor.contains(adapter.composer())) {
      if (adapter.id !== "generic") return; // another field (a search box, a title): not a message
    }
    intercept(e, editor, { kind: "enter", ctrl: e.ctrlKey, meta: e.metaKey });
  }

  function onClick(e) {
    if (!active() || passThrough.has(e)) return;
    const editor = adapter.composer();
    const control = adapter.sendControl(e.target, editor);
    if (!control || !editor) return;
    intercept(e, editor, { kind: "click", control });
  }

  function onSubmit(e) {
    if (!active() || passThrough.has(e)) return;
    const editor = adapter.composer();
    if (!editor || !e.target.contains(editor)) return;
    intercept(e, editor, { kind: "submit", form: e.target });
  }

  function intercept(e, editor, trigger) {
    const text = readText(editor);
    // The guard's own re-send comes first: it happens while a decision is still marked as open.
    if (bypass && bypass.text === text && Date.now() < bypass.until) return;
    if (busy) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }
    if (!text.trim()) return;
    const cached = cache.get(text);
    if (cached && (!cached.enabled || PASSES.has(cached.decision.action))) {
      if (cached.findings.length) record("noted", "submit", cached);
      return;
    }
    e.preventDefault();
    e.stopImmediatePropagation();
    handleSend(editor, text, trigger, cached);
  }

  async function handleSend(editor, text, trigger, cached) {
    busy = true;
    try {
      let result;
      try {
        result = cached ?? (await scan(text, "submit"));
      } catch (error) {
        const choice = await failure("submit", editor, error);
        if (choice.choice === "send_anyway") {
          record("sent_unchecked", "submit", null, { reason: "check failed" });
          await resend(editor, trigger);
        }
        return;
      }
      for (;;) {
        if (!result.enabled || PASSES.has(result.decision.action)) {
          if (result.findings.length) record("noted", "submit", result);
          await resend(editor, trigger);
          return;
        }
        const choice = await ui.decide({
          mode: "submit", findings: result.findings, decision: result.decision, anchor: editor,
          requireReason: result.requireReason, allowOverride: result.allowOverride, onNotASecret: notASecret,
        });
        if (choice.choice === "recheck") {
          result = await scan(text, "submit");
          continue;
        }
        if (choice.choice === "redact_send" || choice.choice === "redact_review") {
          const redacted = await send("redact", { text, kind: "submit", site: site.id });
          if (!(await writeText(editor, redacted.text))) {
            ui.toast("Shadow Lens could not rewrite the message here. Nothing was sent.");
            return;
          }
          cache.delete(text);
          record("redacted", "submit", result, { review: choice.choice === "redact_review" });
          if (choice.choice === "redact_send") {
            // What remains may still hold something that cannot be replaced (code): that was shown already.
            remember(readText(editor), { ...result, findings: [], decision: { ...result.decision, action: "allow" } });
            await resend(editor, trigger);
          } else {
            ui.toast("Replaced with placeholders. Review the message, then send it.");
            checkTyping(editor);
          }
          return;
        }
        if (choice.choice === "send_anyway") {
          record("sent_anyway", "submit", result, { reason: choice.reason });
          await resend(editor, trigger);
          return;
        }
        record("cancelled", "submit", result);
        editor.focus();
        return;
      }
    } finally {
      busy = false;
    }
  }

  /** Send what is in the editor now, the way the person tried to: their button, Enter, or the form. */
  async function resend(editor, trigger) {
    const text = readText(editor);
    bypass = { text, until: Date.now() + BYPASS_MS };
    await nextFrame();
    let button = trigger.kind === "click" && trigger.control.isConnected ? trigger.control : adapter.findSend(editor);
    // Sites enable their button a moment after the text changes.
    for (let i = 0; i < 20 && button && (button.disabled || button.getAttribute("aria-disabled") === "true"); i++) {
      await new Promise((r) => setTimeout(r, 25));
      button = trigger.kind === "click" && trigger.control.isConnected ? trigger.control : adapter.findSend(editor);
    }
    if (button && !button.disabled) {
      button.click();
      return;
    }
    if (trigger.kind === "submit" && trigger.form?.isConnected) {
      trigger.form.requestSubmit();
      return;
    }
    editor.focus();
    const init = { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true, composed: true, ctrlKey: !!trigger.ctrl, metaKey: !!trigger.meta };
    const down = new KeyboardEvent("keydown", init);
    passThrough.add(down);
    editor.dispatchEvent(down);
    editor.dispatchEvent(new KeyboardEvent("keyup", init));
  }

  // ---------- pasting ----------

  function onPaste(e) {
    if (!active() || !cfg.scanPaste || isWriting() || passThrough.has(e)) return;
    const editor = adapter.editableRoot(e.target);
    const data = e.clipboardData;
    if (!editor || !data) return;
    const files = [...data.files];
    const text = data.getData("text/plain");
    if (!text && !files.length) return;
    // The clipboard data is gone after this event: copy all of it now.
    const strings = {};
    for (const type of data.types) if (type !== "Files") strings[type] = data.getData(type);
    e.preventDefault();
    e.stopImmediatePropagation();
    const saved = saveSelection(editor);
    if (files.length) handleFiles(files, { kind: "paste", editor, saved, strings });
    else handlePaste(editor, saved, strings, text);
  }

  async function handlePaste(editor, saved, strings, text) {
    busy = true;
    try {
      let result;
      try {
        result = await scan(text, "paste");
      } catch (error) {
        const choice = await failure("paste", editor, error);
        if (choice.choice === "paste_anyway") await insertAt(editor, saved, { strings });
        return;
      }
      for (;;) {
        if (!result.enabled || PASSES.has(result.decision.action)) {
          await insertAt(editor, saved, { strings });
          if (result.findings.length) record("noted", "paste", result);
          return;
        }
        const choice = await ui.decide({
          mode: "paste", findings: result.findings, decision: result.decision, anchor: editor,
          requireReason: result.requireReason, allowOverride: result.allowOverride, onNotASecret: notASecret,
        });
        if (choice.choice === "recheck") {
          result = await scan(text, "paste");
          continue;
        }
        if (choice.choice === "paste_redacted") {
          const redacted = await send("redact", { text, kind: "paste", site: site.id, cleanHidden: true });
          // Plain text only: the HTML copy of the clipboard still holds the values.
          await insertAt(editor, saved, { strings: { "text/plain": redacted.text } });
          record("redacted", "paste", result);
        } else if (choice.choice === "paste_clean") {
          await insertAt(editor, saved, { strings: { "text/plain": clean(text) } });
          record("cleaned", "paste", result);
        } else if (choice.choice === "paste_anyway") {
          await insertAt(editor, saved, { strings });
          record("pasted_anyway", "paste", result, { reason: choice.reason });
        } else {
          record("cancelled", "paste", result);
          editor.focus();
        }
        return;
      }
    } finally {
      busy = false;
      checkTyping(editor);
    }
  }

  // ---------- files ----------

  function onChange(e) {
    const input = e.target;
    if (!active() || !cfg.scanFiles || passThrough.has(e) || !(input instanceof HTMLInputElement) || input.type !== "file") return;
    const files = [...(input.files ?? [])];
    if (!files.length) return;
    e.stopImmediatePropagation(); // the site does not hear about the files until they are checked
    handleFiles(files, { kind: "input", input });
  }

  function onInputEventForFiles(e) {
    // Some sites listen for "input" on file fields too: hold it back while the files are checked.
    const input = e.target;
    if (input instanceof HTMLInputElement && input.type === "file" && active() && cfg.scanFiles && !passThrough.has(e)) e.stopImmediatePropagation();
  }

  function onDrop(e) {
    if (!active() || !cfg.scanFiles || passThrough.has(e)) return;
    const data = e.dataTransfer;
    const files = [...(data?.files ?? [])];
    if (!files.length) return;
    const strings = {};
    for (const type of data.types) if (type !== "Files") strings[type] = data.getData(type);
    e.preventDefault();
    e.stopImmediatePropagation();
    handleFiles(files, { kind: "drop", target: e.target, clientX: e.clientX, clientY: e.clientY, strings });
  }

  async function handleFiles(files, origin) {
    busy = true;
    const anchor = adapter.composer();
    try {
      const checked = [];
      const unchecked = [];
      // Documents and images are read in the background and can take a few seconds: say what is happening.
      const reading = files.some(needsReader) ? ui.toast("Reading the file on this device\u2026 nothing leaves it.", 120_000) : null;
      for (const file of files) {
        if (file.size > cfg.maxFileBytes) {
          unchecked.push(`${file.name} (too large to check)`);
          continue;
        }
        const text = await extractText(file, async (doc) => (await send("extract", { name: doc.name, base64: await toBase64(doc) })).text).catch(() => null);
        if (text == null) {
          unchecked.push(`${file.name} (not a text document)`);
          continue;
        }
        checked.push({ file, text, result: await scan(text, "file") });
      }
      reading?.remove();
      const flagged = checked.filter((c) => !c.result.enabled ? false : !PASSES.has(c.result.decision.action));
      if (!flagged.length) {
        if (unchecked.length) ui.toast(`Shadow Lens could not look inside: ${unchecked.join(", ")}.`, 5000);
        for (const c of checked) if (c.result.findings.length) record("noted", "file", c.result, { file: c.file.name });
        deliver(files, origin);
        return;
      }
      const findings = flagged.flatMap((c) => c.result.findings.map((f) => ({ ...f, masked_preview: `${c.file.name}: ${f.masked_preview ?? ""}` })));
      const worst = flagged.map((c) => c.result).sort((a, b) => (b.decision.action === "block") - (a.decision.action === "block"))[0];
      const choice = await ui.decide({
        mode: "file", findings, decision: worst.decision, anchor, fileNames: files.map((f) => f.name),
        requireReason: worst.requireReason, allowOverride: worst.allowOverride, canRedactFile: true, onNotASecret: notASecret,
        note: unchecked.length ? `Not checked: ${unchecked.join(", ")}.` : undefined,
      });
      if (choice.choice === "upload_redacted") {
        const replacements = new Map();
        for (const c of flagged) {
          const redacted = await send("redact", { text: c.text, kind: "file", site: site.id, cleanHidden: true });
          // A document or an image (read as text) becomes its redacted text, so it is renamed and typed as plain text;
          // a text file keeps its name and type.
          const document_ = needsReader(c.file);
          const name = document_ ? `${c.file.name}.redacted.txt` : c.file.name;
          replacements.set(c.file, new File([redacted.text], name, { type: document_ ? "text/plain" : c.file.type || "text/plain", lastModified: Date.now() }));
          record("redacted", "file", c.result, { file: c.file.name });
        }
        deliver(files.map((f) => replacements.get(f) ?? f), origin);
      } else if (choice.choice === "upload_anyway") {
        for (const c of flagged) record("uploaded_anyway", "file", c.result, { file: c.file.name, reason: choice.reason });
        deliver(files, origin);
      } else {
        for (const c of flagged) record("cancelled", "file", c.result, { file: c.file.name });
        if (origin.kind === "input") origin.input.value = "";
      }
    } catch (error) {
      const choice = await failure("file", anchor, error);
      if (choice.choice === "upload_anyway") deliver(files, origin);
      else if (origin.kind === "input") origin.input.value = "";
    } finally {
      busy = false;
    }
  }

  /** Hand the (possibly replaced) files to the site the way they arrived. */
  function deliver(files, origin) {
    const transfer = new DataTransfer();
    for (const f of files) transfer.items.add(f);
    if (origin.kind === "input") {
      origin.input.files = transfer.files;
      for (const type of ["input", "change"]) {
        const event = new Event(type, { bubbles: true });
        passThrough.add(event);
        origin.input.dispatchEvent(event);
      }
    } else if (origin.kind === "drop") {
      for (const [type, value] of Object.entries(origin.strings ?? {})) transfer.setData(type, value);
      const event = new DragEvent("drop", { bubbles: true, cancelable: true, composed: true, clientX: origin.clientX, clientY: origin.clientY, dataTransfer: transfer });
      passThrough.add(event);
      (origin.target.isConnected ? origin.target : document.body).dispatchEvent(event);
    } else if (origin.kind === "paste") {
      dispatchPaste(origin.editor, { strings: origin.strings, files });
    }
  }

  // ---------- wiring ----------

  function on(target, type, handler, options = true) {
    target.addEventListener(type, handler, options);
    listeners.push(() => target.removeEventListener(type, handler, options));
  }

  function attach() {
    on(window, "keydown", onKeydown);
    on(window, "click", onClick);
    on(window, "submit", onSubmit);
    on(window, "paste", onPaste);
    on(window, "drop", onDrop);
    on(window, "change", onChange);
    on(window, "input", onInputEventForFiles);
    on(window, "input", onInput);
    on(window, "focusin", onFocusIn);
    on(window, "focusout", () => setTimeout(() => {
      if (!ui.isOpen() && typingEditor && !typingEditor.contains(document.activeElement) && !lastTyping?.result.findings.length) ui.setBadge(null);
    }, 100));
  }

  function detach() {
    for (const off of listeners.splice(0)) off();
    clearTimeout(typingTimer);
  }

  function setConfig(next) {
    cfg = next;
    cache.clear();
    if (!active()) ui.setBadge(null);
  }

  return { attach, detach, setConfig, isBusy: () => busy };
}

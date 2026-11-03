// What the person sees on the AI site: the decision panel, the badge on the composer, and a layer for the
// "copy with real values" chips. All of it lives in a closed shadow root attached to <html>, outside the
// site's own app, so the site's code cannot read it and its styles cannot reach it. Built with
// textContent only, never innerHTML.

const CSS = `
:host { all: initial; }
* { box-sizing: border-box; }
.layer { position: fixed; inset: 0; pointer-events: none; z-index: 2147483646;
  font: 14px/20px "Hanken Grotesk", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; color: #121A21; }
.layer > * { pointer-events: auto; }
.mono { font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }
.panel { position: fixed; width: min(560px, calc(100vw - 32px)); max-height: min(70vh, 640px); overflow: auto;
  background: #FFFFFF; border: 1px solid #E4E2DA; border-top: 4px solid var(--tone); border-radius: 6px;
  box-shadow: 0 10px 32px rgba(18,26,33,.28); padding: 16px 18px 14px; animation: rise .14s ease-out; }
@keyframes rise { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
.panel[data-tone=red] { --tone: #B3261E; } .panel[data-tone=amber] { --tone: #8F5300; } .panel[data-tone=teal] { --tone: #0B7A75; }
.brand { display: flex; align-items: center; gap: 8px; font: 500 11px/16px "IBM Plex Mono", ui-monospace, monospace;
  letter-spacing: .1em; text-transform: uppercase; color: #4A5866; }
.brand .lens { width: 10px; height: 10px; border-radius: 50%; border: 2px solid #0B7A75; }
.close { margin-left: auto; border: 0; background: none; font-size: 18px; line-height: 1; color: #4A5866; cursor: pointer; padding: 4px; }
h2 { margin: 8px 0 4px; font-size: 17px; line-height: 24px; font-weight: 700; }
.sub { margin: 0 0 12px; color: #4A5866; font-size: 13px; }
ul { list-style: none; margin: 0 0 12px; padding: 0; border-top: 1px solid #E9E8E2; }
li { padding: 10px 0; border-bottom: 1px solid #E9E8E2; }
li.dismissed { opacity: .45; }
.row { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.title { font-weight: 600; }
.sev { font: 500 10px/14px "IBM Plex Mono", ui-monospace, monospace; letter-spacing: .08em; text-transform: uppercase;
  padding: 1px 6px; border-radius: 3px; }
.sev.critical, .sev.high { background: #FBE8E6; color: #B3261E; }
.sev.medium { background: #FBF0DC; color: #8F5300; }
.sev.low { background: #E9E8E2; color: #4A5866; }
.mask { color: #4A5866; font-size: 12px; }
.count { color: #4A5866; font-size: 12px; }
details { margin-top: 4px; font-size: 13px; color: #4A5866; }
summary { cursor: pointer; color: #0B7A75; width: fit-content; }
details p { margin: 6px 0; } details ol { margin: 0; padding-left: 18px; }
.mini { border: 0; background: none; color: #0B7A75; cursor: pointer; font: inherit; font-size: 12px; padding: 0; margin-left: auto; text-decoration: underline; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
button.btn { font: 600 13px/18px inherit; font-family: inherit; border-radius: 6px; padding: 8px 14px; cursor: pointer; border: 1px solid transparent; }
.btn.primary { background: #0B7A75; color: #fff; } .btn.primary:hover { background: #0A6964; }
.btn.secondary { background: #fff; color: #121A21; border-color: #D4D2CA; } .btn.secondary:hover { background: #E9E8E2; }
.btn.quiet { background: none; color: #4A5866; padding-left: 6px; padding-right: 6px; } .btn.quiet:hover { color: #B3261E; }
.btn:disabled { opacity: .5; cursor: default; }
.spacer { flex: 1; }
.reason { display: none; margin-top: 10px; gap: 8px; align-items: center; }
.reason.open { display: flex; }
.reason input { flex: 1; font: inherit; padding: 7px 10px; border: 1px solid #D4D2CA; border-radius: 6px; }
.note { margin-top: 10px; font-size: 12px; color: #4A5866; }
.error { color: #B3261E; }
:focus-visible { outline: 2px solid #0B7A75; outline-offset: 2px; }
.badge { position: fixed; display: none; align-items: center; gap: 6px; padding: 3px 9px 3px 7px; border-radius: 999px;
  background: #FFFFFF; border: 1px solid #E4E2DA; box-shadow: 0 2px 8px rgba(18,26,33,.12); cursor: pointer;
  font: 500 11px/16px "IBM Plex Mono", ui-monospace, monospace; color: #4A5866; }
.badge.show { display: flex; }
.badge i { width: 8px; height: 8px; border-radius: 50%; background: #0B7A75; }
.badge.warn i { background: #8F5300; } .badge.block i { background: #B3261E; }
.badge.block { color: #B3261E; border-color: #F2C7C3; }
.chip { position: fixed; display: flex; align-items: center; gap: 8px; padding: 4px 6px 4px 10px; border-radius: 6px;
  background: #DCEFEC; border: 1px solid #B9DDD8; font-size: 12px; color: #0B4F4B; box-shadow: 0 2px 6px rgba(18,26,33,.1); }
.chip button { font: 600 12px/16px inherit; font-family: inherit; border: 0; border-radius: 4px; background: #0B7A75; color: #fff; padding: 3px 8px; cursor: pointer; }
.toast { position: fixed; right: 16px; bottom: 16px; background: #0E151B; color: #fff; padding: 10px 14px; border-radius: 6px;
  font-size: 13px; box-shadow: 0 10px 24px rgba(18,26,33,.35); }
@media (prefers-color-scheme: dark) {
  .layer { color: #E8EDF1; }
  .panel, .badge { background: #16212A; border-color: #2A3844; }
  .sub, .mask, .count, details, .brand, .badge, .close { color: #9AA7B3; }
  ul, li { border-color: #2A3844; }
  .btn.secondary { background: #16212A; color: #E8EDF1; border-color: #2A3844; }
  .btn.secondary:hover { background: #0E151B; }
  .reason input { background: #0E151B; color: #E8EDF1; border-color: #2A3844; }
  summary, .mini { color: #3FC1B8; }
}
`;

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

const TONE = { block: "red", warn: "amber", note: "teal", allow: "teal" };

function headline(mode, decision, findings) {
  const n = findings.length;
  const thing = n === 1 ? "something" : `${n} things`;
  if (mode === "paste") return decision.action === "block" ? `This paste has ${thing} you should not share` : `Check this paste before it goes in`;
  if (mode === "file") return `This file has ${thing} you should not share`;
  if (mode === "info") return n ? `${n === 1 ? "One thing" : `${n} things`} to look at before sending` : "Nothing sensitive found";
  return decision.action === "block" ? `Shadow Lens stopped this message` : `Check this message before sending`;
}

export function createUI() {
  const host = document.createElement("shadow-lens");
  // Inline !important beats any page stylesheet, so the site cannot hide the panel and leave a message held.
  for (const [name, value] of Object.entries({ all: "initial", position: "fixed", inset: "0", "pointer-events": "none", "z-index": "2147483646", display: "block", visibility: "visible", opacity: "1" })) {
    host.style.setProperty(name, value, "important");
  }
  // Closed: the site's scripts cannot reach in. (The end-to-end test build opens it for the test driver.)
  const root = host.attachShadow({ mode: typeof __SHADOWLENS_TEST__ !== "undefined" && __SHADOWLENS_TEST__ ? "open" : "closed" });
  root.append(h("style", {}, CSS));
  const layer = h("div", { class: "layer" });
  root.append(layer);
  document.documentElement.append(host);
  // ...and if the page removes it, it goes back.
  const keeper = new MutationObserver(() => {
    if (!host.isConnected) document.documentElement.append(host);
  });
  keeper.observe(document.documentElement, { childList: true });

  let open = null; // { panel, finish }

  function place(panel, anchor) {
    const rect = anchor?.getBoundingClientRect?.();
    const width = Math.min(560, innerWidth - 32);
    if (rect && rect.width) {
      const left = Math.max(16, Math.min(rect.left + (rect.width - width) / 2, innerWidth - width - 16));
      panel.style.left = `${left}px`;
      const above = rect.top - 12;
      if (above > 260) panel.style.bottom = `${innerHeight - above}px`;
      else panel.style.top = `${Math.min(rect.bottom + 12, innerHeight - 200)}px`;
    } else {
      panel.style.left = `${(innerWidth - width) / 2}px`;
      panel.style.bottom = "24px";
    }
  }

  function close(result = { choice: "cancel" }) {
    if (!open) return;
    const { panel, finish } = open;
    open = null;
    panel.remove();
    finish(result);
  }

  /**
   * Show the decision panel and wait for the person's choice.
   * opts: { mode: "submit"|"paste"|"file"|"info", findings, decision, requireReason, allowOverride, anchor,
   *         fileNames, onNotASecret(finding) => Promise<boolean> }
   * Resolves to { choice, reason? }.
   */
  function decide(opts) {
    close();
    const { mode, findings, decision } = opts;
    const blocked = decision.action === "block";
    const needReason = blocked && opts.requireReason;
    const canOverride = !blocked || opts.allowOverride;
    const redactable = findings.some((f) => f.redactable);
    const hidden = findings.some((f) => f.rule_id === "HIDDEN_TEXT");
    const dismissed = new Set();

    return new Promise((resolve) => {
      const finish = (result) => resolve(result);
      const choose = (choice, extra = {}) => close({ choice, ...extra });

      const list = h("ul", {}, findings.map((f) => {
        const item = h("li", {},
          h("div", { class: "row" },
            h("span", { class: "title" }, f.title),
            h("span", { class: `sev ${f.severity}` }, f.severity),
            f.masked_preview ? h("span", { class: "mask mono" }, f.masked_preview) : null,
            f.count > 1 ? h("span", { class: "count" }, `×${f.count}`) : null,
            f.kind === "secret" || f.kind === "personal"
              ? h("button", { class: "mini", type: "button", onclick: async (e) => {
                  e.target.disabled = true;
                  const ok = await opts.onNotASecret?.(f);
                  if (ok) {
                    dismissed.add(f);
                    item.classList.add("dismissed");
                    e.target.textContent = "Will not be flagged again";
                    if (dismissed.size === findings.length) setTimeout(() => choose("recheck"), 400);
                  } else e.target.disabled = false;
                } }, "Not a secret")
              : null),
          h("details", {},
            h("summary", {}, "Why this matters"),
            h("p", {}, f.why),
            h("ol", {}, f.fix.map((step) => h("li", { style: "border:0;padding:2px 0" }, step)))));
        return item;
      }));

      const reasonInput = h("input", { type: "text", placeholder: "Why is it fine to send? (kept only in your history)", maxlength: "300", "aria-label": "Reason" });
      const confirmAnyway = h("button", { class: "btn secondary", type: "button", disabled: true, onclick: () => choose(anyway, { reason: reasonInput.value.trim() }) }, mode === "paste" ? "Paste anyway" : mode === "file" ? "Upload anyway" : "Send anyway");
      reasonInput.addEventListener("input", () => (confirmAnyway.disabled = reasonInput.value.trim().length < 3));
      reasonInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !confirmAnyway.disabled) confirmAnyway.click();
        e.stopPropagation();
      });
      const reasonRow = h("div", { class: "reason" }, reasonInput, confirmAnyway);

      const anyway = mode === "paste" ? "paste_anyway" : mode === "file" ? "upload_anyway" : "send_anyway";
      const anywayLabel = mode === "paste" ? "Paste anyway" : mode === "file" ? "Upload anyway" : "Send anyway";
      const anywayButton = canOverride && mode !== "info"
        ? h("button", { class: "btn quiet", type: "button", onclick: () => {
            if (!needReason) return choose(anyway);
            reasonRow.classList.add("open");
            reasonInput.focus();
          } }, needReason ? `${anywayLabel}…` : anywayLabel)
        : null;

      const buttons = [];
      if (mode === "submit" || mode === "info") {
        if (redactable) buttons.push(h("button", { class: "btn primary", type: "button", onclick: () => choose(mode === "info" ? "redact_review" : "redact_send") }, mode === "info" ? "Redact now" : "Redact & send"));
        if (redactable && mode === "submit") buttons.push(h("button", { class: "btn secondary", type: "button", onclick: () => choose("redact_review") }, "Redact, let me review"));
        buttons.push(h("button", { class: "btn secondary", type: "button", onclick: () => choose("cancel") }, mode === "info" ? "Close" : "Edit message"));
      } else if (mode === "paste") {
        if (redactable) buttons.push(h("button", { class: "btn primary", type: "button", onclick: () => choose("paste_redacted") }, hidden ? "Paste redacted & cleaned" : "Paste redacted"));
        else if (hidden) buttons.push(h("button", { class: "btn primary", type: "button", onclick: () => choose("paste_clean") }, "Paste cleaned"));
        buttons.push(h("button", { class: "btn secondary", type: "button", onclick: () => choose("cancel") }, "Don't paste"));
      } else if (mode === "file") {
        if (redactable && opts.canRedactFile) buttons.push(h("button", { class: "btn primary", type: "button", onclick: () => choose("upload_redacted") }, "Upload a redacted copy"));
        buttons.push(h("button", { class: "btn secondary", type: "button", onclick: () => choose("remove") }, "Don't upload"));
      }

      const sub = mode === "file"
        ? `${(opts.fileNames ?? []).join(", ")}. Nothing has been uploaded yet.`
        : mode === "paste"
          ? "Nothing has been pasted yet. Only you can see this."
          : mode === "info"
            ? "Checked on this device. Nothing has been sent."
            : "Nothing has been sent. Only you can see this.";

      const panel = h("section", { class: "panel", role: "dialog", "aria-modal": "true", "aria-label": "Shadow Lens", "data-tone": TONE[decision.action] ?? "teal" },
        h("div", { class: "brand" }, h("span", { class: "lens" }), "Shadow Lens",
          h("button", { class: "close", type: "button", "aria-label": "Close", onclick: () => choose("cancel") }, "×")),
        h("h2", {}, headline(mode, decision, findings)),
        h("p", { class: "sub" }, sub),
        list,
        h("div", { class: "actions" }, buttons, h("span", { class: "spacer" }), anywayButton),
        reasonRow,
        opts.note ? h("p", { class: "note" }, opts.note) : null);
      panel.addEventListener("keydown", (e) => {
        if (e.key === "Escape") choose("cancel");
        e.stopPropagation(); // keys typed in the panel are not the site's business
      });
      place(panel, opts.anchor);
      layer.append(panel);
      open = { panel, finish };
      (panel.querySelector(".btn.primary") ?? panel.querySelector(".btn"))?.focus();
    });
  }

  // ---- badge on the composer ----
  const badge = h("div", { class: "badge", role: "button", tabindex: "0", "aria-live": "polite" }, h("i"), h("span"));
  layer.append(badge);
  let badgeAnchor = null;
  let badgeClick = null;
  badge.addEventListener("click", () => badgeClick?.());
  badge.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && badgeClick?.());

  function placeBadge() {
    if (!badgeAnchor || !badge.classList.contains("show")) return;
    const r = badgeAnchor.getBoundingClientRect();
    if (!r.width) return;
    badge.style.left = `${Math.max(8, r.right - badge.offsetWidth - 8)}px`;
    badge.style.top = `${Math.max(8, r.top - badge.offsetHeight - 6)}px`;
  }
  addEventListener("scroll", placeBadge, { passive: true, capture: true });
  addEventListener("resize", placeBadge, { passive: true });
  // Composers grow and move as the conversation does; follow them while the badge shows.
  const follow = setInterval(placeBadge, 400);

  /** state: { anchor, findings, action } or null to hide. */
  function setBadge(state, onClick) {
    badgeClick = onClick;
    if (!state || !state.anchor) {
      badge.classList.remove("show");
      return;
    }
    if (!state.anchor.isConnected) {
      badge.classList.remove("show");
      return;
    }
    badgeAnchor = state.anchor;
    const n = state.findings.length;
    badge.className = `badge show ${state.action === "block" ? "block" : state.action === "warn" ? "warn" : ""}`;
    badge.lastChild.textContent = n ? `Shadow Lens · ${n} to review` : "Shadow Lens";
    badge.title = n ? state.findings.map((f) => f.title).join(", ") : "Protected: checked on this device";
    placeBadge();
  }

  /** A short notice. Returns `{ remove }` for one that should go as soon as the work it reports is done. */
  function toast(message, ms = 3500) {
    const t = h("div", { class: "toast", role: "status" }, message);
    layer.append(t);
    const timer = setTimeout(() => t.remove(), ms);
    return { remove: () => (clearTimeout(timer), t.remove()) };
  }

  function destroy() {
    close();
    clearInterval(follow);
    keeper.disconnect();
    host.remove();
    removeEventListener("scroll", placeBadge, { capture: true });
    removeEventListener("resize", placeBadge);
  }

  return { decide, close, isOpen: () => !!open, setBadge, toast, layer, h, destroy, host };
}

// Confirmation dialog (Frontend Design PDF p6). Focus stays inside; Esc or the scrim cancels.
import { el } from "../ui.js";
import { button } from "./primitives.js";
import { overlayIn, overlayOut } from "../motion.js";

export function openModal({ label, title, body, confirmLabel, cancelLabel = "Cancel", onConfirm, onCancel }) {
  const previous = document.activeElement;
  const done = (fn) => () => { close(); fn?.(); };
  const confirmBtn = button({ label: confirmLabel, onClick: done(onConfirm) });
  const cancelBtn = button({ label: cancelLabel, variant: "secondary", onClick: done(onCancel) });
  const dialog = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": "modal-title", "aria-describedby": "modal-body" },
    el("div", { class: "label" }, label),
    el("h2", { class: "modal__title", id: "modal-title" }, title),
    el("p", { class: "modal__body", id: "modal-body" }, body),
    el("div", { class: "modal__actions" }, confirmBtn, cancelBtn));
  const scrim = el("div", { class: "scrim" }, dialog);

  function onKey(e) {
    if (e.key === "Escape") { e.preventDefault(); done(onCancel)(); }
    if (e.key === "Tab") {
      const first = confirmBtn, last = cancelBtn;
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }
  scrim.addEventListener("click", (e) => { if (e.target === scrim) done(onCancel)(); });
  document.addEventListener("keydown", onKey);
  document.body.append(scrim);
  overlayIn(scrim, dialog);
  confirmBtn.focus();

  function close() {
    document.removeEventListener("keydown", onKey);
    scrim.style.pointerEvents = "none";
    overlayOut([scrim], {}, () => scrim.remove());
    previous?.focus?.();
  }
  return close;
}

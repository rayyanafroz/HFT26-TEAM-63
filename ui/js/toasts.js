// Toast host. Stack at top right over page content (design p3). Duration and stack size are not specified (UD-07):
// alert and info toasts close after 8 s, error toasts stay until closed, at most 3 are shown.
import { el } from "./ui.js";
import { toast as makeToast } from "./components/primitives.js";
import { overlayIn, overlayOut } from "./motion.js";

const MAX = 3;
const AUTO_CLOSE_MS = 8000;
let host = null;

export function mountToastHost(parent = document.body) {
  host = el("div", { class: "toast-host", "aria-live": "polite", "aria-label": "Notifications" });
  parent.append(host);
  return host;
}

/** show({ variant: "alert"|"info"|"error", label, title, text, linkLabel, href, onRetry }) -> close() */
export function showToast(opts = {}) {
  if (!host) mountToastHost();
  const { href, onRetry, className, ...rest } = opts;
  let timer = null;
  const close = () => { clearTimeout(timer); overlayOut(node, { x: 24 }, () => node.remove()); };
  const node = makeToast({
    ...rest,
    onClose: close,
    onLink: href ? () => { window.location.hash = href; close(); } : undefined,
    onRetry: onRetry ? () => { close(); onRetry(); } : undefined,
  });
  if (className) node.classList.add(className);
  host.prepend(node);
  overlayIn(null, node, { x: 24 });
  while (host.children.length > MAX) host.lastElementChild.remove();
  if (opts.variant !== "error") timer = setTimeout(close, AUTO_CLOSE_MS);
  return close;
}

export const toasts = {
  alert: (a) => showToast({
    variant: "alert",
    className: `toast--sev-${a.severity}`,
    label: `${a.severity === "critical" ? "Critical" : "High"} alert`,
    title: a.title,
    text: a.finding?.summary ?? undefined,
    linkLabel: "Open alert",
    href: `#/alerts?alert=${encodeURIComponent(a.id)}`,
  }),
  info: (title, text, label = "Scenario") => showToast({ variant: "info", label, title, text }),
  error: (title, text, onRetry) => showToast({ variant: "error", label: "Error", title, text, onRetry }),
};

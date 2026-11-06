// Small helpers shared by the popup and the options page.

export async function ask(type, payload = {}) {
  const reply = await chrome.runtime.sendMessage({ type, ...payload });
  if (reply?.error) throw new Error(reply.error);
  return reply;
}

export function h(tag, attrs = {}, ...children) {
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

export const ACTION_LABELS = {
  redacted: "Redacted",
  cleaned: "Cleaned",
  sent_anyway: "Sent anyway",
  pasted_anyway: "Pasted anyway",
  uploaded_anyway: "Uploaded anyway",
  sent_unchecked: "Sent unchecked",
  cancelled: "Stopped",
  noted: "Noted",
};

export function actionTone(action) {
  if (["sent_anyway", "pasted_anyway", "uploaded_anyway", "sent_unchecked"].includes(action)) return "red";
  if (["redacted", "cleaned", "cancelled"].includes(action)) return "teal";
  return "";
}

export function sevTone(severity) {
  return severity === "critical" || severity === "high" ? "red" : severity === "medium" ? "amber" : "";
}

export function when(time) {
  const d = new Date(time);
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString([], { month: "short", day: "numeric" });
}

export function siteName(sites, id) {
  return sites.find((s) => s.id === id)?.name ?? id;
}

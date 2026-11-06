// Guard. What the browser extension stopped before it reached an AI tool, from GET /api/guard/summary and
// GET /api/guard/events. Events hold masks ("sk-p... (len 56)") and keyed hashes, never the text.
import { el, fmtNumber } from "../ui.js";
import { watch, load } from "./util.js";

const TOPICS = ["guardSummary", "guardEvents"];

const SITE_NAMES = {
  chatgpt: "ChatGPT", claude: "Claude", gemini: "Gemini", copilot: "Microsoft Copilot", perplexity: "Perplexity",
  deepseek: "DeepSeek", mistral: "Mistral Le Chat",
};
const SOURCE_NAMES = { browser: "Browser", claude_code: "Claude Code", clipboard: "Clipboard", cli: "Scan command" };
const ACTIONS = {
  redacted: ["Redacted", "tone-green"], cleaned: ["Cleaned", "tone-green"], cancelled: ["Stopped", "tone-green"], blocked: ["Blocked", "tone-green"],
  sent_anyway: ["Sent anyway", "tone-red"], pasted_anyway: ["Pasted anyway", "tone-red"], uploaded_anyway: ["Uploaded anyway", "tone-red"],
  sent_unchecked: ["Sent unchecked", "tone-red"], noted: ["Noted", ""], warned: ["Warned", "tone-amber"], allowed: ["Allowed", ""],
};
const KINDS = { submit: "message", paste: "paste", file: "upload", typing: "message", prompt: "prompt" };

const siteName = (id) => SITE_NAMES[id] ?? id;

/** "14:02" today, "3 Nov 14:02" on other days: guard events span weeks. */
function when(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "\u2013";
  const time = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  if (d.toDateString() === new Date().toDateString()) return time;
  return `${d.getDate()} ${d.toLocaleString("en", { month: "short" })} ${time}`;
}

export function mount(container, ctx) {
  const { store, live, primitives: P } = ctx;
  const root = el("div", { class: "guard" });
  container.append(
    el("header", { class: "screen-head" },
      el("h1", { class: "h2" }, "Guard"),
      el("p", { class: "small" }, "What Shadow Lens stopped before it reached an AI tool, in the browser and on this computer. Values are shown as masks only.")),
    root);

  function tile(label, value, sub, tone = "") {
    return el("section", { class: "card ov-tile" },
      el("h2", { class: "label" }, label),
      el("div", { class: `ov-tile__val ${tone}` }, value),
      sub ? el("div", { class: "ov-tile__sub" }, sub) : null);
  }

  function dailyCard(s) {
    const max = Math.max(1, ...s.daily.map((d) => d.stopped + d.let_through));
    return el("section", { class: "card guard-daily" },
      el("h2", { class: "label card__label" }, `Last ${s.days} days`),
      el("div", { class: "guard-cols", role: "img", "aria-label": `${s.totals.stopped} stopped and ${s.totals.let_through} let through in ${s.days} days` },
        ...s.daily.map((d) => el("div", { class: "guard-col", title: `${d.day}: ${d.stopped} stopped, ${d.let_through} let through` },
          el("span", { class: "guard-col__through", style: `height:${(d.let_through / max) * 100}%` }),
          el("span", { class: "guard-col__stopped", style: `height:${(d.stopped / max) * 100}%` })))),
      el("div", { class: "guard-legend small" },
        el("span", {}, el("i", { class: "guard-key guard-key--stopped" }), "Stopped or redacted"),
        el("span", {}, el("i", { class: "guard-key guard-key--through" }), "Let through anyway")));
  }

  function barCard(title, rows, empty) {
    const max = Math.max(1, ...rows.map((r) => r.count));
    return el("section", { class: "card" },
      el("h2", { class: "label card__label" }, title),
      rows.length
        ? el("ul", { class: "barlist" }, ...rows.slice(0, 8).map((r) => el("li", {},
            el("span", { class: "barlist__name", title: r.name }, r.name),
            el("span", { class: "barlist__track barlist__track--tint" }, el("span", { class: "barlist__fill", style: `width:${(r.count / max) * 100}%` })),
            el("span", { class: "barlist__num" }, fmtNumber(r.count)))))
        : el("p", { class: "small" }, empty));
  }

  function connectionCard(s) {
    const browserSeen = s.last_browser_event_at;
    return el("section", { class: "card card--tint guard-conn" },
      el("h2", { class: "label card__label" }, "Connection"),
      el("p", {}, s.companion_installed ? "The browser extension can reach this dashboard." : "The browser extension is not connected to this dashboard yet."),
      browserSeen ? el("p", { class: "small" }, `Last event from the browser: ${when(browserSeen)}.`) : null,
      s.companion_installed ? null : el("p", { class: "small" }, "Install the extension (extension/dist), then run ",
        el("code", { class: "mono" }, "python -m shadowlens.native_host install"), " and restart the browser."));
  }

  function eventsTable(items) {
    if (!items.length) return el("p", { class: "table-none" }, "Nothing yet. Events appear here the moment the guard acts.");
    const head = el("thead", {}, el("tr", {}, ...["When", "Where", "What happened", "What was found"].map((h) => el("th", { scope: "col" }, h))));
    const body = el("tbody", {}, ...items.map((e) => {
      const [label, tone] = ACTIONS[e.action] ?? [e.action, ""];
      return el("tr", {},
        el("td", { class: "mono-cell" }, when(e.at)),
        el("td", {}, siteName(e.site), el("div", { class: "small" }, `${SOURCE_NAMES[e.source] ?? e.source} · ${KINDS[e.kind] ?? e.kind}`)),
        el("td", {}, el("strong", { class: tone }, label), e.reason ? el("div", { class: "small" }, `“${e.reason}”`) : null),
        el("td", {}, e.findings.length
          ? e.findings.slice(0, 4).map((f) => el("div", { class: "guard-find" }, f.severity ? P.sevMark(f.severity) : null,
              el("span", {}, f.title), f.masked_preview ? el("span", { class: "mono small" }, f.masked_preview) : null))
          : el("span", { class: "small" }, "–")));
    }));
    return el("div", { class: "table-scroll" }, el("table", { class: "table guard-table" }, head, body));
  }

  function render() {
    const entry = store.state("guardSummary");
    const s = entry.data;
    if (!s && entry.status === "error") {
      root.replaceChildren(el("section", { class: "card" }, P.errorBlock({ message: `Could not load the guard summary. ${entry.error.message}`, onRetry: () => load(store, TOPICS) })));
      return;
    }
    if (!s) { root.replaceChildren(el("section", { class: "card" }, P.loadingText("Loading…"))); return; }
    const events = store.get("guardEvents")?.items ?? [];
    const sites = s.sites.filter((r) => r.stopped + r.let_through).map((r) => ({ name: siteName(r.site), count: r.stopped + r.let_through }));
    const rules = s.rules.map((r) => ({ name: r.title, count: r.count }));
    const sitesUsed = s.sites.length;
    root.replaceChildren(
      el("div", { class: "guard-top" },
        tile("Stopped", fmtNumber(s.totals.stopped), `redacted, cleaned or not sent · ${s.days} days`, s.totals.stopped ? "tone-green" : ""),
        tile("Let through anyway", fmtNumber(s.totals.let_through), s.totals.let_through ? "sent after a warning" : "none", s.totals.let_through ? "tone-red" : ""),
        tile("Noted", fmtNumber(s.totals.noted), "low-risk, passed quietly"),
        tile("Sites", fmtNumber(sitesUsed), sitesUsed ? Object.entries(s.sources).map(([k, n]) => `${SOURCE_NAMES[k] ?? k} ${n}`).join(" · ") : "none yet"),
        connectionCard(s)),
      el("div", { class: "guard-mid" },
        dailyCard(s),
        barCard("Where", sites, "Nothing stopped yet."),
        barCard("What was found", rules, "Nothing found yet.")),
      el("section", { class: "card guard-events" },
        el("h2", { class: "label card__label" }, "Latest events"),
        eventsTable(events)));
  }

  const off = watch(store, TOPICS, render);
  const offLive = [live.on("guard.new", () => load(store, TOPICS))];
  render();
  load(store, TOPICS);
  return () => { off(); offLive.forEach((f) => f()); };
}

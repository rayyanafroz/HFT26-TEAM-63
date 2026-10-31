// Leak Lab (Frontend Design PDF p12). Text is sent to the local service only (POST /api/analyze/preview), 250 ms after typing stops.
// Sample buttons fetch fake inputs from GET /api/analyze/samples, so no token-shaped text lives in the UI code.
import { el } from "../ui.js";

const DEBOUNCE_MS = 250;
const MAX_CHARS = 20000;

export function mount(container, ctx) {
  const { api, primitives: P } = ctx;
  let mode = "text";
  let timer = null;
  let seq = 0;
  let result = null;          // last good Preview
  let state = "idle";         // idle | loading | ready | error
  let error = null;

  /* ---------- input side ---------- */
  const mirror = el("div", { class: "lab__mirror", "aria-hidden": "true" });
  const area = el("textarea", { class: "lab__area", id: "lab-input", spellcheck: "false", "aria-label": "Text to analyze",
    placeholder: "Type or paste a prompt, or load a fake sample." });
  const note = el("p", { class: "lab__note" }, "Nothing typed here is stored. It is analyzed on this machine.");
  const over = el("p", { class: "lab__over", hidden: true }, `Only the first ${MAX_CHARS.toLocaleString("en")} characters are analyzed.`);
  area.addEventListener("input", () => { paintMirror(); schedule(); });
  area.addEventListener("scroll", () => { mirror.scrollTop = area.scrollTop; });

  const modeSeg = P.segmented({ items: [{ id: "text", label: "Prompt text" }, { id: "agent_json", label: "Agent request JSON" }], selected: "text",
    onSelect: (id) => { mode = id; schedule(true); } });
  const sampleErr = el("span", { class: "card-error", hidden: true });
  const samples = el("div", { class: "lab__samples" },
    ...[["key", "Fake key"], ["pii", "Fake customer data"], ["agent", "Fake agent tool call"]].map(([k, l]) =>
      P.button({ label: l, variant: "small", onClick: () => loadSample(k) })),
    sampleErr);

  async function loadSample(kind) {
    sampleErr.hidden = true;
    try {
      const s = await api.get("/api/analyze/samples");
      area.value = s[kind] ?? "";
      if ((kind === "agent") !== (mode === "agent_json")) modeSeg.querySelectorAll(".chip")[kind === "agent" ? 1 : 0].click();
      paintMirror(); schedule(true);
      area.focus();
    } catch (err) {
      sampleErr.hidden = false;
      sampleErr.textContent = `Could not load the sample. ${err.message}`;
    }
  }

  /* ---------- analysis ---------- */
  function schedule(now) {
    clearTimeout(timer);
    timer = setTimeout(run, now ? 0 : DEBOUNCE_MS);
  }
  async function run() {
    const text = area.value.slice(0, MAX_CHARS);
    over.hidden = area.value.length <= MAX_CHARS;
    if (!text.trim()) { result = null; state = "idle"; paint(); return; }
    const mine = ++seq;
    state = "loading"; paintStatus();
    try {
      const r = await api.post("/api/analyze/preview", { text, mode });
      if (mine !== seq) return;               // a newer request is on its way
      result = { ...r, text }; state = "ready"; error = null;
    } catch (err) {
      if (mine !== seq) return;
      state = "error"; error = err;
    }
    paint();
  }

  /* Highlights drawn behind a transparent textarea. Spans index into the submitted text. */
  function paintMirror() {
    const text = area.value;
    const spans = result && result.text === text.slice(0, MAX_CHARS)
      ? [...result.findings].filter((f) => Array.isArray(f.span) && f.span[0] < f.span[1] && f.span[1] <= text.length).sort((a, b) => a.span[0] - b.span[0])
      : [];
    const parts = [];
    let at = 0;
    for (const f of spans) {
      const [s, e] = f.span;
      if (s < at) continue;                    // overlapping spans: the first one wins
      parts.push(text.slice(at, s));
      parts.push(el("mark", { class: `lab__mark lab__mark--${f.category === "secret" ? "secret" : "data"}` }, text.slice(s, e)));
      at = e;
    }
    parts.push(text.slice(at), "\n");
    mirror.replaceChildren(...parts);
  }

  /* ---------- result side ---------- */
  const status = el("span", { class: "lab__status", role: "status" });
  const findingsBox = el("div", {});
  const receiveBox = el("div", {});
  const guardBox = el("div", {});
  const riskBox = el("div", {});

  function paintStatus() {
    status.textContent = state === "loading" ? "Analyzing…" : "";
  }

  function paint() {
    paintStatus();
    paintMirror();
    if (state === "error" && !result) {
      findingsBox.replaceChildren(el("div", { class: "lab__pad" }, P.errorBlock({ message: `Could not analyze the text. ${error.message}`, onRetry: () => schedule(true) })));
    } else if (!result) {
      findingsBox.replaceChildren(el("p", { class: "lab__pad small" }, "Type or paste text, or load a fake sample. Findings appear here."));
    } else if (!result.findings.length) {
      findingsBox.replaceChildren(el("p", { class: "lab__pad small" }, "No findings in this text."));
    } else {
      findingsBox.replaceChildren(el("div", { class: "table-scroll" }, el("table", { class: "table lab__table" },
        el("thead", {}, el("tr", {}, ...["Rule", "Severity", "Preview", "Confidence"].map((h) => el("th", { scope: "col" }, h)))),
        el("tbody", {}, ...result.findings.map((f) => el("tr", {},
          el("td", { class: "mono" }, f.rule_id),
          el("td", {}, P.sevMark(f.severity)),
          el("td", { class: "mono" }, f.masked_preview),
          el("td", { class: "mono" }, Number(f.confidence).toFixed(2))))))));
    }
    if (state === "error" && result) findingsBox.prepend(el("div", { class: "lab__pad" }, el("div", { class: "card-error" }, `Could not analyze the latest text. ${error.message}`,
      el("button", { class: "linkbtn", type: "button", onClick: () => schedule(true) }, "Retry"))));
    receiveBox.replaceChildren(result ? P.codeBlock(result.redacted_text) : el("p", { class: "small" }, "The redacted text appears here."));
    guardBox.replaceChildren(el("div", { class: `lab__big ${result ? (result.would_block ? "tone-red" : "tone-green") : ""}` }, result ? `Would be blocked: ${result.would_block ? "yes" : "no"}` : "–"));
    riskBox.replaceChildren(result
      ? el("div", { class: "lab__risk" }, el("span", { class: "lab__riskval" }, `+${Number(result.points_preview.S).toFixed(1)}`),
          el("span", { class: "lab__risksub" }, `tool score ${Number(result.points_preview.tool_score).toFixed(1)}`))
      : el("div", { class: "lab__big" }, "–"));
  }

  container.append(
    el("header", { class: "screen-head screen-head--row" },
      el("div", {}, el("h1", { class: "h2" }, "Leak Lab"), el("p", { class: "small" }, "Test the detector on your own text.")),
      el("span", { class: "head-note" }, "analysis runs 250 ms after you stop typing")),
    el("div", { class: "lab" },
      el("section", { class: "card lab__input" },
        el("div", { class: "lab__head" }, el("h2", { class: "label" }, "Input"), modeSeg),
        samples,
        el("div", { class: "lab__head" }, el("label", { class: "label", for: "lab-input" }, "Annotated input"), status),
        el("div", { class: "lab__box" }, mirror, area),
        over, note),
      el("div", { class: "lab__side" },
        el("section", { class: "card lab__findings" }, el("h2", { class: "label lab__pad" }, "Findings"), findingsBox),
        el("section", { class: "card" }, el("h2", { class: "label card__label" }, "What the AI model would receive"), receiveBox),
        el("div", { class: "lab__pair" },
          el("section", { class: "card" }, el("h2", { class: "label" }, "Guard result"), guardBox),
          el("section", { class: "card" }, el("h2", { class: "label" }, "Risk added"), riskBox)))));
  paint();
  return () => { clearTimeout(timer); seq++; };
}

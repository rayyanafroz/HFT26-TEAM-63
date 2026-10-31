// ShadowLens pitch (#/pitch). A presentation layer inside the dashboard.
// Motion: GSAP + ScrollTrigger (sections animate as they enter), Vanta FOG behind the hero only.
// The Quick Leak section is a scripted UI animation with SOT 8.2 numbers. It makes no backend calls and shows no secret value.
import { el, svg } from "../ui.js";
import { logoMark } from "../components/primitives.js";
import { loadGsap, loadVanta } from "../vendor.js";

const SECTIONS = [
  { id: "problem", n: "01", label: "The problem" },
  { id: "solution", n: "02", label: "What it is" },
  { id: "how", n: "03", label: "How it works" },
  { id: "demo", n: "04", label: "Quick Leak demo" },
  { id: "why", n: "05", label: "Why ShadowLens" },
];

function ensureStyles() {
  if (document.getElementById("pitch-css")) return;
  document.head.append(el("link", { rel: "stylesheet", href: "pitch.css", id: "pitch-css" }));
}

export function mount(container, ctx) {
  ensureStyles();
  const { primitives: P } = ctx;
  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  let alive = true;
  let gsapCtx = null;
  let vanta = null;
  const cleanups = [];

  /* ---------- builders ---------- */
  const label = (text) => el("div", { class: "p-label" }, text);
  const head = (s, headline, line) => el("header", { class: "p-head", dataset: { anim: "head" } },
    label(`${s.n} · ${s.label}`), el("h2", { class: "p-h2", id: `p-${s.id}-title` }, headline), line ? el("p", { class: "p-lede" }, line) : null);
  const go = (href) => () => { location.hash = href; };
  const cta = (text, onClick, variant = "primary") => el("button", { class: `p-btn p-btn--${variant}`, type: "button", onClick }, text);

  /* Brand diagram: device → AI tools. Solid = seen, dashed = not seen, one teal edge where seen ends. */
  function diagram(seen) {
    const tools = [["Cloud AI", "api.openai.com"], ["Local model", "port 11434"], ["Coding agent", "shell · files · network"], ["Browser AI tool", "HTTPS body"]];
    const W = 560, H = 300, bx = 16, bw = 196, tx = 352, tw = 192, cy = H / 2;
    const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "p-diagram", role: "img",
      "aria-label": seen ? "This laptop to four AI tools. Three links are seen. The browser AI tool body is not seen." : "This laptop to four AI tools. No link is seen." });
    tools.forEach(([name, sub], i) => {
      const y = 22 + i * 70;
      const isSeen = seen && i < 3;
      g.append(svg("line", { x1: bx + bw, y1: cy, x2: tx, y2: y + 24, class: `p-dg__link${isSeen ? " is-seen" : ""}`, "data-x2": tx, "data-y2": y + 24 }));
      g.append(svg("g", { class: "p-dg__tool" },
        svg("rect", { x: tx, y, width: tw, height: 48, class: "p-dg__box" }),
        svg("text", { x: tx + 14, y: y + 21, class: "p-dg__name", text: name }),
        svg("text", { x: tx + 14, y: y + 38, class: "p-dg__sub", text: !seen || isSeen ? sub : "not seen · metadata only" })));
    });
    g.append(svg("g", { class: "p-dg__src" },
      svg("rect", { x: bx, y: cy - 34, width: bw, height: 68, class: "p-dg__box p-dg__box--src" }),
      svg("text", { x: bx + 14, y: cy - 6, class: "p-dg__name", text: "This laptop" }),
      svg("text", { x: bx + 14, y: cy + 14, class: "p-dg__sub", text: "processes · ports · apps" })));
    if (seen) g.append(svg("line", { x1: tx - 18, y1: 10, x2: tx - 18, y2: 22 + 2 * 70 + 58, class: "p-dg__edge" }));
    else g.append(svg("text", { x: 282, y: cy + 4, "text-anchor": "middle", class: "p-dg__q", text: "?" }));
    return g;
  }

  /* ---------- hero ---------- */
  const vantaHost = el("div", { class: "p-vanta", "aria-hidden": "true" });
  const heroScore = el("span", { class: "p-score__num" }, "52");
  const hero = el("section", { class: "p-sec p-hero p-night", "aria-labelledby": "p-hero-title" },
    vantaHost, el("div", { class: "p-hero__shade", "aria-hidden": "true" }),
    el("div", { class: "p-wrap p-split" },
      el("div", { class: "p-claim", dataset: { anim: "hero" } },
        label("Local AI exposure scanner"),
        el("h1", { class: "p-display", id: "p-hero-title" }, "See which AI tools got your secrets."),
        el("p", { class: "p-lede" }, "Rules you can read. Blind spots it names."),
        el("div", { class: "p-ctas" },
          cta("Watch the Quick Leak demo", () => scrollTo("demo")),
          cta("Run a local scan", go("#/capture?view=controls"), "ghost"))),
      el("div", { class: "p-panel p-heroscore", "aria-label": "Sample score" },
        label("Score · quick_leak, simulated"),
        el("div", { class: "p-score" }, heroScore, el("span", { class: "p-score__band" }, "Elevated")),
        el("div", { class: "p-mono p-row" }, "SEC_AWS_SECRET_KEY", el("span", {}, "54.0")),
        el("div", { class: "p-mono p-row" }, "POLICY_UNSANCTIONED_TOOL", el("span", {}, "4.5")),
        el("div", { class: "p-cov" },
          el("div", { class: "p-cov__bar" }, el("div", { class: "p-cov__seen", style: "width:62%" }), el("div", { class: "p-cov__unseen" })),
          el("div", { class: "p-cov__nums p-mono" }, el("span", {}, "full 62%"), el("span", {}, "metadata only 38%"))))));

  /* ---------- 01 problem ---------- */
  const problem = el("section", { class: "p-sec p-night", id: "p-problem", "aria-labelledby": "p-problem-title" },
    el("div", { class: "p-wrap p-split" },
      el("div", { class: "p-claim" },
        head(SECTIONS[0], "Secrets leave laptops for AI tools nobody listed.", "Cloud AI, local models and coding agents run with no oversight."),
        el("ul", { class: "p-chips", dataset: { anim: "stagger" } },
          ...["Keys in prompts", "Customer data in chats", "Agents with shells"].map((t) => el("li", {}, t)))),
      el("figure", { class: "p-evidence", dataset: { anim: "diagram" } },
        el("div", { class: "p-panel p-panel--flat" }, diagram(false)),
        el("figcaption", { class: "p-cap" }, "Every link is dashed. Nobody sees it."))));

  /* ---------- 02 solution ---------- */
  const solution = el("section", { class: "p-sec p-paper", id: "p-solution", "aria-labelledby": "p-solution-title" },
    el("div", { class: "p-wrap p-split" },
      el("div", { class: "p-claim" },
        head(SECTIONS[1], "ShadowLens: a local, passive AI exposure scanner.", "No HTTPS decryption. Nothing installed on other machines."),
        el("dl", { class: "p-pairs", dataset: { anim: "stagger" } },
          ...[["Finds", "AI tools in use"], ["Shows", "what reached them, masked"], ["Maps", "agent access, granted vs used"], ["Scores", "risk with a readable formula"]]
            .map(([k, v]) => el("div", { class: "p-pair" }, el("dt", {}, k), el("dd", {}, v))))),
      el("figure", { class: "p-evidence", dataset: { anim: "diagram" } },
        el("div", { class: "p-panel p-panel--light" }, diagram(true)),
        el("figcaption", { class: "p-cap" }, "Solid = seen. The browser body stays metadata only, and it says so."))),
    el("div", { class: "p-wrap" },
      el("div", { class: "p-principles", dataset: { anim: "stagger" } },
        ...[["Passive", "Read-only."], ["Local first", "Binds to 127.0.0.1."], ["No raw secrets", "Never stored or sent."], ["Honest visibility", "Full or metadata only."]]
          .map(([k, v]) => el("div", { class: "p-principle" }, el("div", { class: "p-principle__k" }, k), el("p", {}, v))))));

  /* ---------- 03 how it works ---------- */
  const steps = [
    ["Observe", "conn_scan · log upload · live log"],
    ["Classify", "api.openai.com → OpenAI"],
    ["Detect", "SEC_AWS_SECRET_KEY · ••••x9Qz"],
    ["Score", "54.0 + 4.5 = 58.5 → 52"],
    ["Act", "Masked alert, next step"],
  ];
  const pipeScan = el("span", { class: "p-pipe__scan", "aria-hidden": "true" });
  const how = el("section", { class: "p-sec p-night p-night--surface", id: "p-how", "aria-labelledby": "p-how-title" },
    el("div", { class: "p-wrap" },
      head(SECTIONS[2], "Rules decide. The AI model only advises.", "Deterministic detection. AI sees redacted text and never changes a score."),
      el("div", { class: "p-pipewrap" },
        el("ol", { class: "p-pipe", "aria-label": "Detection pipeline" },
          ...steps.map(([k, m], i) => el("li", { class: "p-pipe__step" },
            el("div", { class: "p-pipe__n p-mono" }, String(i + 1).padStart(2, "0")),
            el("h3", { class: "p-pipe__t" }, k),
            el("div", { class: "p-pipe__m p-mono" }, m)))),
        pipeScan),
      el("p", { class: "p-note" }, "Only full-visibility events are inspected. HTTPS is metadata only.")));

  /* ---------- 04 quick leak demo ---------- */
  const demoSteps = ["Activity", "Reaches OpenAI", "Key typed", "Detected", "Finding", "Risk 0 → 52", "Next step"];
  const progress = el("ol", { class: "q-progress", "aria-label": "Demo steps" }, ...demoSteps.map((s, i) => el("li", { dataset: { i } }, el("span", { class: "p-mono" }, i + 1), s)));
  const packet = el("span", { class: "q-packet", "aria-hidden": "true" });
  const log = el("ol", { class: "q-log p-mono", "aria-label": "Simulated activity" },
    ...[1, 2, 3, 4, 5].map((n) => el("li", { class: "q-log__row" }, el("span", {}, `t ${(n * 0.9).toFixed(1)} s`), el("span", {}, `python3 → api.openai.com · prompt ${n}`), el("span", { class: "q-ok" }, "no finding"))));
  const typed = el("span", { class: "q-typed" });
  const mask = el("span", { class: "q-mask" });
  const caret = el("span", { class: "q-caret", "aria-hidden": "true" });
  const hit = el("span", { class: "q-hit" }, "aws_secret_access_key = ", mask);
  const composer = el("div", { class: "q-composer p-mono", "aria-label": "Prompt 6, with the key masked" },
    el("div", { class: "q-composer__label" }, "prompt 6 · t 6.0 s"),
    el("div", { class: "q-composer__text" }, typed, hit, caret),
    el("span", { class: "q-sweep", "aria-hidden": "true" }));
  const fired = el("div", { class: "q-fired p-mono" }, "SEC_AWS_SECRET_KEY fired · value masked before storage");
  const riskNum = el("span", { class: "q-risk__num" }, "52");
  const riskFill = el("span", { class: "q-risk__fill" });
  const waiting = el("div", { class: "q-waiting p-mono" }, "Waiting for a finding…");
  const finding = el("div", { class: "q-finding" },
    el("div", { class: "q-finding__title" }, P.sevMark("critical"), el("strong", {}, "AWS secret key sent in a prompt")),
    el("div", { class: "p-mono q-finding__meta" }, "python3 · OpenAI · unapproved"),
    el("dl", { class: "q-kv" },
      el("dt", {}, "Masked value"), el("dd", { class: "p-mono" }, "••••••••••••••x9Qz"),
      el("dt", {}, "Rule"), el("dd", { class: "p-mono q-pts" }, "SEC_AWS_SECRET_KEY", el("span", {}, "54.0")),
      el("dt", {}, "Rule"), el("dd", { class: "p-mono q-pts" }, "POLICY_UNSANCTIONED_TOOL", el("span", {}, "4.5"))));
  const risk = el("div", { class: "q-risk" },
    el("div", {}, el("div", { class: "p-label" }, "Org risk"),
      el("div", { class: "q-risk__line" }, riskNum, el("span", { class: "q-risk__band" }, "Elevated"))),
    el("div", { class: "q-risk__bar" }, riskFill),
    el("div", { class: "p-mono q-risk__calc" }, "58.5 points → tool score 52 → org risk 52"));
  const remedy = el("div", { class: "q-remedy" },
    el("div", { class: "p-label" }, "What the AI model received"),
    el("pre", { class: "p-code" }, "Alert: SEC_AWS_SECRET_KEY, severity critical.\nContext: aws_secret_access_key = [REDACTED]"),
    el("p", { class: "q-next" }, el("strong", {}, "Next step: "), "rotate the key, then remove it from shell history."));
  const replay = el("button", { class: "q-replay", type: "button" }, "Replay demo");

  const demo = el("section", { class: "p-sec p-paper", id: "p-demo", "aria-labelledby": "p-demo-title" },
    el("div", { class: "p-wrap" },
      head(SECTIONS[3], "A fake AWS key reached an unapproved AI tool.", null),
      el("div", { class: "q-bar" }, el("span", { class: "q-badge p-mono" }, "Controlled demo · simulated data · no scanner calls"), replay),
      progress,
      el("div", { class: "q-stage" },
        el("div", { class: "q-left" },
          el("div", { class: "q-flow" },
            el("div", { class: "q-node" }, el("strong", {}, "python3"), el("span", { class: "p-mono" }, "this laptop")),
            el("div", { class: "q-line" }, packet, el("span", { class: "q-line__tap p-mono" }, "seen by ShadowLens")),
            el("div", { class: "q-node q-node--ai" }, el("strong", {}, "OpenAI"), el("span", { class: "p-mono" }, "not approved"))),
          log, composer, fired),
        el("div", { class: "q-window", "aria-live": "polite" },
          el("div", { class: "q-window__bar" }, el("span", { class: "p-mono" }, "Alert detail"), el("span", { class: "p-tag" }, "quick_leak")),
          el("div", { class: "q-window__body" }, waiting, finding, risk, remedy))),
      el("div", { class: "p-ctas p-ctas--row" },
        cta("Try it in Leak Lab", go("#/lab")), cta("Read how scoring works", go("#/compliance?tab=why"), "ghost-dark"))));

  /* ---------- 05 why / close ---------- */
  const finalMark = logoMark({ size: 72, night: true });
  finalMark.setAttribute("aria-hidden", "true"); finalMark.removeAttribute("role"); finalMark.removeAttribute("aria-label");
  const why = el("section", { class: "p-sec p-night p-close", id: "p-why", "aria-labelledby": "p-why-title" },
    el("div", { class: "p-wrap" },
      head(SECTIONS[4], "It names its blind spots.", "Every score traces to a rule. Every gap is said out loud."),
      el("div", { class: "p-split p-split--top" },
        el("div", { class: "p-values", dataset: { anim: "stagger" } },
          ...[["Show the working", "A Why panel for every point."], ["Keep data local", "Redacted before any AI sees it."],
            ["Rules decide", "The model never changes a score."], ["Agents mapped", "Granted against used."]]
            .map(([k, v]) => el("div", { class: "p-value" }, el("h3", {}, k), el("p", {}, v)))),
        el("div", { class: "p-panel p-limits" },
          label("What it cannot see"),
          el("ul", { class: "p-limitlist", dataset: { anim: "stagger" } },
            ...["HTTPS bodies", "Browser traffic without a HAR export", "MCP servers over stdio", "Other users' processes, without elevated rights",
              "Connections under about 2 s", "Cloud hosts in a live scan, unless the hostname is known"]
              .map((t) => el("li", {}, el("span", { class: "p-limitmark", "aria-hidden": "true" }), t)))))),
    el("div", { class: "p-wrap p-final", dataset: { anim: "final" } },
      el("div", { class: "p-final__lockup" }, finalMark, el("span", { class: "p-final__word" }, "ShadowLens")),
      el("p", { class: "p-final__line" }, "The AI exposure scanner that shows its blind spots."),
      el("div", { class: "p-ctas" }, cta("Run a local scan", go("#/capture?view=controls")), cta("Open the dashboard", go("#/home"), "ghost"))));

  /* ---------- rail ---------- */
  const railItems = SECTIONS.map((s) => el("li", {},
    el("button", { class: "p-rail__btn", type: "button", "aria-label": `${s.n} ${s.label}`, onClick: () => scrollTo(s.id) },
      el("span", { class: "p-mono" }, s.n), el("span", { class: "p-rail__text", "aria-hidden": "true" }, s.label))));
  const railFill = el("span", { class: "p-rail__fill" });
  const rail = el("nav", { class: "p-rail", "aria-label": "Pitch sections" }, el("span", { class: "p-rail__track", "aria-hidden": "true" }, railFill), el("ol", {}, ...railItems));

  const page = el("div", { class: `pitch${reduced ? " is-reduced" : ""}` }, hero, problem, solution, how, demo, why, rail);
  container.append(page);
  document.title = "ShadowLens · Pitch";
  window.scrollTo(0, 0);

  function scrollTo(id) {
    document.getElementById(`p-${id}`)?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
  }

  /* ---------- rail follows scroll ---------- */
  const secs = SECTIONS.map((s) => document.getElementById(`p-${s.id}`));
  const onScroll = () => {
    const mid = window.innerHeight * 0.4;
    let active = -1;
    secs.forEach((s, i) => { if (s.getBoundingClientRect().top <= mid) active = i; });
    railItems.forEach((li, i) => { const b = li.firstElementChild; if (i === active) b.setAttribute("aria-current", "true"); else b.removeAttribute("aria-current"); });
    const total = page.scrollHeight - window.innerHeight;
    railFill.style.height = `${(total > 0 ? Math.min(1, Math.max(0, window.scrollY / total)) * 100 : 0).toFixed(1)}%`;
    rail.classList.toggle("is-visible", window.scrollY > hero.offsetHeight * 0.5);
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  cleanups.push(() => window.removeEventListener("scroll", onScroll));
  onScroll();

  /* ---------- sticky panels: a section taller than the screen sticks by its bottom edge, so all of it is read first ---------- */
  const panels = [hero, problem, solution, how, demo, why];
  const desktop = () => window.innerWidth > 960;
  const setSticks = () => panels.forEach((s) => s.style.setProperty("--stick", desktop() ? `${Math.min(0, window.innerHeight - s.offsetHeight)}px` : "0px"));
  setSticks();
  const ro = new ResizeObserver(() => { setSticks(); window.ScrollTrigger?.refresh(); });
  panels.forEach((s) => ro.observe(s));
  window.addEventListener("resize", setSticks);
  cleanups.push(() => { ro.disconnect(); window.removeEventListener("resize", setSticks); });

  /* ---------- splash ---------- */
  const splashDone = showPitchSplash(reduced);

  /* ---------- motion ---------- */
  const demoTl = { current: null };
  function setFinalDemoState() {   // static frame: used for reduced motion and as the end state
    typed.textContent = "Deploy with ";
    mask.textContent = "";
    mask.classList.add("is-redacted");
    caret.hidden = true;
    composer.classList.add("is-hit");
    [fired, finding, risk, remedy].forEach((n) => { n.style.opacity = "1"; });
    waiting.style.display = "none";
    riskNum.textContent = "52";
    riskFill.style.width = "52%";
    progress.querySelectorAll("li").forEach((li) => li.classList.add("is-done"));
  }

  if (reduced) {
    setFinalDemoState();
    replay.hidden = true;
  } else {
    loadGsap().then((gsap) => {
      if (!alive) return;
      const ST = window.ScrollTrigger;
      gsapCtx = gsap.context(() => {
        // hero intro, after the splash
        const heroTl = gsap.timeline({ paused: true });
        heroTl.from(hero.querySelectorAll("[data-anim='hero'] > *"), { y: 24, opacity: 0, duration: 0.6, stagger: 0.09, ease: "power3.out" })
          .from(hero.querySelector(".p-heroscore"), { x: 32, opacity: 0, duration: 0.6, ease: "power3.out" }, 0.15)
          .fromTo(heroScore, { textContent: 0 }, { textContent: 52, duration: 0.9, snap: { textContent: 1 }, ease: "power2.out" }, 0.4)
          .from(hero.querySelectorAll(".p-row"), { opacity: 0, x: -10, stagger: 0.12, duration: 0.3 }, 0.6)
          .from(hero.querySelector(".p-cov__seen"), { scaleX: 0, transformOrigin: "0% 50%", duration: 0.7, ease: "power2.out" }, 0.7);
        splashDone.then(() => alive && heroTl.play());

        // section heads and lists
        page.querySelectorAll("[data-anim='head']").forEach((h) => {
          gsap.from(h.children, { y: 26, opacity: 0, duration: 0.6, stagger: 0.08, ease: "power3.out", scrollTrigger: { trigger: h, start: "top 82%", once: true } });
        });
        page.querySelectorAll("[data-anim='stagger']").forEach((list) => {
          gsap.from(list.children, { y: 16, opacity: 0, duration: 0.45, stagger: 0.08, ease: "power2.out", scrollTrigger: { trigger: list, start: "top 85%", once: true } });
        });

        // diagrams: boxes appear, links extend from the laptop, the teal edge grows
        page.querySelectorAll("[data-anim='diagram']").forEach((fig) => {
          const links = fig.querySelectorAll(".p-dg__link");
          const tl = gsap.timeline({ scrollTrigger: { trigger: fig, start: "top 75%", once: true } });
          tl.from(fig.querySelector(".p-dg__src"), { opacity: 0, x: -16, duration: 0.4 })
            .from(fig.querySelectorAll(".p-dg__tool"), { opacity: 0, x: 16, stagger: 0.1, duration: 0.4 }, 0.1);
          links.forEach((ln, i) => tl.from(ln, { attr: { x2: ln.getAttribute("x1"), y2: ln.getAttribute("y1") }, duration: 0.45, ease: "power2.out" }, 0.35 + i * 0.12));
          const edge = fig.querySelector(".p-dg__edge");
          if (edge) tl.from(edge, { scaleY: 0, transformOrigin: "50% 0%", duration: 0.5, ease: "power2.out" }, ">-0.1");
          const q = fig.querySelector(".p-dg__q");
          if (q) tl.from(q, { opacity: 0, scale: 0.6, transformOrigin: "50% 50%", duration: 0.3 }, ">");
          tl.from(fig.querySelector(".p-cap"), { opacity: 0, duration: 0.3 }, ">-0.1");
        });

        // pipeline: a scan line crosses the five steps; each lights up as it passes
        const pipe = how.querySelector(".p-pipe");
        const stepsEls = pipe.querySelectorAll(".p-pipe__step");
        const ptl = gsap.timeline({ scrollTrigger: { trigger: pipe, start: "top 75%", once: true } });
        ptl.set(stepsEls, { opacity: 0.18 })
          .fromTo(pipeScan, { left: "0%", opacity: 1 }, { left: "100%", duration: 1.6, ease: "none" })
          .to(stepsEls, { opacity: 1, duration: 0.3, stagger: 0.32 }, 0.05)
          .from(pipe.querySelectorAll(".p-pipe__m"), { y: 8, opacity: 0, duration: 0.3, stagger: 0.32 }, 0.15)
          .to(pipeScan, { opacity: 0, duration: 0.2 });

        // closing lockup
        const fin = why.querySelector("[data-anim='final']");
        gsap.from(fin.children, { y: 20, opacity: 0, duration: 0.6, stagger: 0.12, ease: "power3.out", scrollTrigger: { trigger: fin, start: "top 85%", once: true } });

        // the Quick Leak demo
        demoTl.current = buildDemo(gsap);
        ST.create({
          trigger: demo.querySelector(".q-stage"), start: "top 70%", end: "bottom 15%",
          onEnter: () => demoTl.current.restart(), onEnterBack: () => demoTl.current.restart(),
          onLeave: () => demoTl.current.pause(), onLeaveBack: () => demoTl.current.pause(),
        });
        replay.addEventListener("click", () => demoTl.current.restart());

        // hand-off between panels: as the next panel rises, the one under it eases up and dims (scrubbed, so it follows the scroll)
        const mm = gsap.matchMedia();
        cleanups.push(() => mm.revert());
        mm.add("(min-width: 961px)", () => {
          panels.slice(1).forEach((next, i) => {
            const prevWrap = panels[i].querySelectorAll(":scope > .p-wrap");
            gsap.to(prevWrap, { y: "-6vh", opacity: 0.25, ease: "none",
              scrollTrigger: { trigger: next, start: "top bottom", end: "top top", scrub: 0.4 } });
          });
        });

        // Vanta behind the hero only; created when the hero is on screen, destroyed when it leaves
        ST.create({ trigger: hero, start: "top bottom", end: "bottom top", onToggle: (self) => (self.isActive ? startVanta() : stopVanta()) });
      }, page);
    }).catch(() => setFinalDemoState());
  }

  function buildDemo(gsap) {
    const rows = log.querySelectorAll(".q-log__row");
    const prog = progress.querySelectorAll("li");
    const mark = (i) => () => prog.forEach((li, j) => { li.classList.toggle("is-on", j === i); li.classList.toggle("is-done", j < i); });
    const typeText = (target, text, perChar) => {
      const o = { n: 0 };
      return gsap.to(o, { n: text.length, duration: text.length * perChar, ease: "none", onUpdate: () => { target.textContent = text.slice(0, Math.round(o.n)); } });
    };
    const firstFrame = () => {
      typed.textContent = ""; mask.textContent = ""; mask.classList.remove("is-redacted"); caret.hidden = false;
      composer.classList.remove("is-hit");
      waiting.style.display = ""; riskNum.textContent = "0"; riskFill.style.width = "0%";
      prog.forEach((li) => li.classList.remove("is-on", "is-done"));
      gsap.set([rows, composer, fired, finding, risk, remedy], { opacity: 0 });
      gsap.set(rows, { y: 8 });
      gsap.set(packet, { left: "0%", opacity: 0 });
    };
    firstFrame();     // nothing is shown before the section enters view
    const tl = gsap.timeline({ paused: true });
    tl.call(firstFrame)
      // Pacing: about 15 s in total, with a pause after each step so it can be read.
      // 1 activity
      .call(mark(0))
      .to(rows, { opacity: 1, y: 0, duration: 0.35, stagger: 0.4 })
      // 2 each prompt travels to OpenAI
      .call(mark(1), null, 0.6)
      .to(packet, { keyframes: [{ left: "0%", opacity: 1, duration: 0 }, { left: "100%", duration: 0.7, ease: "power1.inOut" }, { opacity: 0, duration: 0.15 }], repeat: 2 }, 0.6)
      // 3 prompt 6 is typed; the key itself appears only as mask characters
      .call(mark(2), null, "+=0.6")
      .to(composer, { opacity: 1, duration: 0.35 })
      .add(typeText(typed, "Deploy with ", 0.08))
      .add(typeText(mask, "••••••••••••••••••", 0.055), "+=0.15")
      .to(packet, { keyframes: [{ left: "0%", opacity: 1, duration: 0 }, { left: "100%", duration: 0.8, ease: "power1.inOut" }, { opacity: 0, duration: 0.15 }] }, "+=0.2")
      // 4 the scan sweep crosses the prompt and the rule fires
      .call(mark(3), null, "+=0.4")
      .fromTo(composer.querySelector(".q-sweep"), { left: "0%", opacity: 1 }, { left: "100%", duration: 1.0, ease: "power2.out" })
      .call(() => { composer.classList.add("is-hit"); mask.textContent = ""; mask.classList.add("is-redacted"); caret.hidden = true; }, null, "<0.65")
      .to(composer.querySelector(".q-sweep"), { opacity: 0, duration: 0.15 })
      .to(fired, { opacity: 1, duration: 0.4 })
      // 5 the finding appears
      .call(mark(4), null, "+=0.7")
      .call(() => { waiting.style.display = "none"; })
      .fromTo(finding, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: 0.5, ease: "power2.out" })
      .from(finding.querySelectorAll("dt, dd"), { opacity: 0, x: -8, duration: 0.3, stagger: 0.15 }, "<0.25")
      // 6 risk 0 → 52
      .call(mark(5), null, "+=0.7")
      .fromTo(risk, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: 0.4 })
      .fromTo(riskNum, { textContent: 0 }, { textContent: 52, duration: 1.8, snap: { textContent: 1 }, ease: "power2.out" }, "<0.15")
      .fromTo(riskFill, { width: "0%" }, { width: "52%", duration: 1.8, ease: "power2.out" }, "<")
      // 7 what the model received, and the next step
      .call(mark(6), null, "+=0.7")
      .fromTo(remedy, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: 0.5 })
      .call(() => prog.forEach((li) => { li.classList.remove("is-on"); li.classList.add("is-done"); }), null, "+=0.8");
    return tl;
  }

  async function startVanta() {
    if (vanta || reduced || window.innerWidth < 760) return;
    try {
      const VANTA = await loadVanta();
      if (!alive || vanta) return;
      vanta = VANTA.FOG({
        el: vantaHost, mouseControls: false, touchControls: false, gyroControls: false,
        highlightColor: 0x3fc1b8, midtoneColor: 0x16212a, lowlightColor: 0x0e151b, baseColor: 0x0e151b,
        blurFactor: 0.62, speed: 0.55, zoom: 0.75,
      });
    } catch { /* no WebGL: the plain night ground stays */ }
  }
  function stopVanta() { vanta?.destroy(); vanta = null; }

  return {
    update(params) { if (params.section) scrollTo(params.section); },
    unmount() {
      alive = false;
      cleanups.forEach((f) => f());
      gsapCtx?.revert();          // kills every tween, timeline and ScrollTrigger made for this page
      stopVanta();
      document.querySelector(".p-splash")?.remove();
    },
  };
}

/** A short branded reveal, not a loading state. Resolves when it has gone. */
function showPitchSplash(reduced) {
  const mark = logoMark({ size: 88, night: true });
  mark.removeAttribute("role"); mark.removeAttribute("aria-label");
  const node = el("div", { class: `p-splash${reduced ? " is-still" : ""}`, "aria-hidden": "true" },
    el("div", { class: "p-splash__grid" }), el("div", { class: "p-splash__sweep" }),
    el("div", { class: "p-splash__center" }, mark, el("div", { class: "p-splash__word" }, "ShadowLens"),
      el("div", { class: "p-splash__tag" }, "The AI exposure scanner that shows its blind spots.")));
  document.body.append(node);
  const hold = reduced ? 500 : 1300;
  return new Promise((resolve) => {
    setTimeout(() => node.classList.add("is-leaving"), hold);
    setTimeout(() => { node.remove(); resolve(); }, hold + 420);
  });
}

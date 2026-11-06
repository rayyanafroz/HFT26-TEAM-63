// Tests for the landing page: the demo runs the real engine, every example behaves as the page says,
// nothing is requested from outside, and the layout holds at phone width.
//   node site/build.mjs && node --test site/test.mjs

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = createRequire(join(here, "..", "extension", "package.json"))("playwright");

let server, browser, base;
const requests = [];
const cspViolations = [];

before(async () => {
  // The real production server, so the Content-Security-Policy it sends is enforced in these tests.
  // SITE_URL=https://... runs the same tests against a deployed copy instead.
  if (process.env.SITE_URL) {
    base = process.env.SITE_URL.replace(/\/$/, "");
  } else {
    const { spawn } = await import("node:child_process");
    const port = 20000 + Math.floor(Math.random() * 20000);
    server = spawn(process.execPath, [join(here, "dist", "server.mjs")], { env: { ...process.env, PORT: String(port) }, stdio: ["ignore", "pipe", "inherit"] });
    await new Promise((resolve, reject) => {
      server.stdout.on("data", (d) => String(d).includes("Shadow Lens site") && resolve());
      server.on("exit", (code) => reject(new Error(`server exited ${code}`)));
    });
    base = `http://localhost:${port}`;
  }
  browser = await chromium.launch({ channel: "chromium" });
});
after(async () => {
  await browser?.close();
  server?.kill();
});

async function open(viewport = { width: 1440, height: 900 }, scheme = "light") {
  const page = await browser.newPage({ viewport, colorScheme: scheme });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("request", (r) => requests.push(r.url()));
  page.on("console", (m) => /content security policy/i.test(m.text()) && cspViolations.push(m.text()));
  await page.goto(base);
  await page.waitForFunction(() => !document.getElementById("verdict").textContent.includes("Loading"));
  return { page, errors };
}

const EXPECT = {
  prompt: { verdict: /stopped/i, found: ["OpenAI API key"], output: /\[OPENAI_API_KEY_1\]/ },
  env: { verdict: /stopped/i, found: ["Database connection string", "AWS access key ID", "GitHub token", "OpenAI API key"], output: /\[DATABASE_URL_1\]/ },
  pii: { verdict: /stopped/i, found: ["Payment card number", "Aadhaar number", "US Social Security number", "Email address", "Phone number"], output: /\[CARD_NUMBER_1\]/ },
  disguised: { verdict: /stopped/i, found: ["OpenAI API key"], output: /\[OPENAI_API_KEY_1\]/ },
  hidden: { verdict: /stopped/i, found: ["Hidden characters or instructions"], output: /summarise this article/ },
  clean: { verdict: /safe to send/i, found: [], output: /reverse a linked list/ },
};

for (const [name, want] of Object.entries(EXPECT)) {
  test(`example "${name}" does what the page says`, async () => {
    const { page, errors } = await open();
    await page.click(`[data-preset="${name}"]`);
    await page.waitForFunction((w) => document.getElementById("verdict").textContent.length > 0, want);
    assert.match(await page.locator("#verdict").innerText(), want.verdict);
    const found = await page.locator("#findings .t").allInnerTexts();
    for (const title of want.found) assert.ok(found.some((f) => f.startsWith(title)), `${name}: missing "${title}" in ${JSON.stringify(found)}`);
    if (!want.found.length) assert.equal(await page.locator("#findings-wrap").isHidden(), true);
    assert.match(await page.locator("#output").innerText(), want.output);
    assert.deepEqual(errors, []);
    await page.close();
  });
}

test("the original secrets never appear in the output or the findings", async () => {
  const { page } = await open();
  await page.click('[data-preset="env"]');
  await page.waitForFunction(() => document.querySelectorAll("#findings li").length >= 4);
  const out = (await page.locator("#output").innerText()) + (await page.locator("#findings").innerText());
  for (const secret of ["S3cretPassw0rd", "Q7W3E9R2T5Y1U8I4", "aB3dE5fG7hI9jK1l", "9fK2mQ7xLw0Zr4Tb"]) assert.ok(!out.includes(secret), secret);
  await page.close();
});

test("typing is checked live, and the restore switch swaps placeholders for the real value", async () => {
  const { page } = await open();
  await page.fill("#input", "nothing here");
  await page.waitForFunction(() => /safe to send/i.test(document.getElementById("verdict").textContent));
  const key = "sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd";
  await page.fill("#input", `use ${key} now`);
  await page.waitForFunction(() => /stopped/i.test(document.getElementById("verdict").textContent));
  assert.match(await page.locator("#reply-text").innerText(), /\[OPENAI_API_KEY_1\]/);
  await page.locator("label.switch").click(); // the visible switch, as a person clicks it
  await page.waitForFunction(() => document.getElementById("restore").checked);
  assert.ok((await page.locator("#reply-text").innerText()).includes(key));
  assert.equal(await page.locator(".editor__marks mark").count(), 1);
  await page.close();
});

test("nothing is requested from outside the page's own origin", async () => {
  const { page } = await open();
  await page.click('[data-preset="disguised"]');
  await page.waitForTimeout(300);
  await page.close();
  const outside = requests.filter((u) => !u.startsWith(base));
  assert.deepEqual(outside, []);
});

test("the layout holds at phone width and the page has one h1 and ordered sections", async () => {
  const { page } = await open({ width: 390, height: 800 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, "no horizontal scroll");
  assert.equal(await page.locator("h1").count(), 1);
  assert.equal(await page.locator('nav a:visible').count() >= 2, true);
  await page.close();
});

test("the copy buttons copy the command", async () => {
  const { page } = await open();
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.locator(".copy").first().click();
  assert.match(await page.evaluate(() => navigator.clipboard.readText()), /npm install/);
  await page.close();
});

test("dark mode renders without errors", async () => {
  const { page, errors } = await open({ width: 1200, height: 800 }, "dark");
  assert.deepEqual(errors, []);
  await page.close();
});

test("the strict Content-Security-Policy is sent and the page does not break it", async () => {
  const { page, errors } = await open();
  await page.click('[data-preset="env"]');
  await page.locator("label.switch").click();
  await page.waitForTimeout(300);
  assert.deepEqual(cspViolations, []);
  assert.deepEqual(errors, []);
  const response = await page.request.get(base);
  const headers = response.headers();
  assert.match(headers["content-security-policy"], /script-src 'self' 'wasm-unsafe-eval'/);
  assert.equal(headers["x-content-type-options"], "nosniff");
  assert.equal(headers["x-frame-options"], "DENY");
  await page.close();
});

test("the server serves the page and the engine, and nothing else", async () => {
  const get = (path, init) => fetch(base + path, init);
  assert.equal((await get("/")).status, 200);
  const wasm = await get("/shadowlens_engine.wasm");
  assert.equal(wasm.headers.get("content-type"), "application/wasm");
  for (const hidden of ["/server.mjs", "/package.json", "/.env", "/..%2Fserver.mjs", "/%2e%2e/server.mjs", "/fonts/", "/nope"]) {
    const status = (await get(hidden)).status;
    assert.ok(status === 404 || status === 400, `${hidden} was ${status}: refused either way, never served`);
  }
  assert.equal((await get("/", { method: "POST" })).status, 405);
  if (!process.env.SITE_URL) assert.equal((await get("/healthz")).status, 200);  // our own server only
  const first = await get("/");
  const again = await get("/", { headers: { "if-none-match": first.headers.get("etag") } });
  assert.equal(again.status, 304);
  assert.ok(Number((await get("/demo.js", { headers: { "accept-encoding": "br" } })).headers.get("content-length")) < 20000, "compressed");
});

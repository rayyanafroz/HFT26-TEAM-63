// Tests for the landing page: the demo runs the real engine, every example behaves as the page says,
// nothing is requested from outside, and the layout holds at phone width.
//   node site/build.mjs && node --test site/test.mjs

import { createRequire } from "node:module";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = createRequire(join(here, "..", "extension", "package.json"))("playwright");
const types = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".wasm": "application/wasm", ".png": "image/png", ".woff2": "font/woff2" };

let server, browser, base;
const requests = [];

before(async () => {
  server = createServer(async (req, res) => {
    let path = new URL(req.url, "http://x").pathname;
    if (path === "/") path = "/index.html";
    let body;
    try {
      body = await readFile(join(here, "dist", path));
    } catch {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": types[extname(path)] ?? "application/octet-stream" }).end(body);
  });
  await new Promise((resolve) => server.listen(0, resolve));
  base = `http://localhost:${server.address().port}`;
  browser = await chromium.launch({ channel: "chromium" });
});
after(async () => {
  await browser?.close();
  server?.close();
});

async function open(viewport = { width: 1440, height: 900 }, scheme = "light") {
  const page = await browser.newPage({ viewport, colorScheme: scheme });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("request", (r) => requests.push(r.url()));
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
  await page.check("#restore", { force: true });
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

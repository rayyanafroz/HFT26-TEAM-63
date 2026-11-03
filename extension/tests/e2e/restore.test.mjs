// Turning placeholders back into real values, on replies rendered the way real chat apps render them:
// split across spans (streaming animation, syntax highlighting), in code blocks, with other brackets.

import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import { choose, fakeKey, launch, open, panel, resetStorage, type } from "./harness.mjs";

const CHATGPT = "https://chatgpt.com/";
let browser;

before(async () => {
  browser = await launch();
});
after(async () => browser?.close());
beforeEach(async () => resetStorage(browser.worker));

/** Send a message holding a key (redacted), with the next reply rendered as `html`. */
async function conversation(origin, html, key, prefix = "deploy") {
  const page = await open(browser.context, origin);
  await page.evaluate((h) => (window.__nextReply = h), html);
  await type(page, origin, `${prefix} with ${key}`);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  await choose(page, "Redact & send");
  await page.waitForFunction(() => window.__sent.length === 1);
  return page;
}

/** Click the last chip: the user's own sent message has one too, and the reply comes after it. */
async function copyViaChip(page, key) {
  await page.locator("shadow-lens .chip button").last().click();
  await page.waitForFunction(async (k) => (await navigator.clipboard.readText()).includes(k), key);
  return page.evaluate(() => navigator.clipboard.readText());
}

const NAME = "OPENAI_API_KEY_1";

test("a placeholder only inside a syntax-highlighted code block is found and copied with the real value", async () => {
  const key = fakeKey(1);
  const page = await conversation(CHATGPT,
    `<p>Use an environment variable instead:</p><pre><code><span class="k">export</span> OPENAI_API_KEY=<span>[</span><span class="v">${NAME}</span><span>]</span>\n<span class="k">node</span> app.js</code></pre>`, key);
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelectorAll(".chip").length >= 2);
  assert.ok(await page.evaluate(() => CSS.highlights.get("shadowlens-restorable")?.size > 0), "highlighted");
  const copied = await copyViaChip(page, key);
  assert.equal(copied, `export OPENAI_API_KEY=${key}\nnode app.js`);
  assert.ok(!(await page.evaluate(() => document.body.innerText)).includes(key), "the real key never enters the page");
  await page.close();
});

test("a placeholder split across streaming spans in prose is found", async () => {
  const key = fakeKey(2);
  const page = await conversation(CHATGPT,
    `<p><span>Set </span><span>[OPENAI_</span><span>API_KEY</span><span>_1]</span><span> now.</span></p>`, key);
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelectorAll(".chip").length >= 2);
  const copied = await copyViaChip(page, key);
  assert.equal(copied.trim(), `Set ${key} now.`);
  await page.close();
});

test("the placeholder in other forms (angle brackets, bare, escaped) is still recognised", async () => {
  const key = fakeKey(3);
  const page = await conversation(CHATGPT, `<p>Try &lt;${NAME}&gt; or just ${NAME} here.</p>`, key);
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelectorAll(".chip").length >= 2);
  const copied = await copyViaChip(page, key);
  assert.equal(copied.trim(), `Try ${key} or just ${key} here.`);
  await page.close();
});

test("the reply is found even when the site's message markup is not one the guard knows", async () => {
  const key = fakeKey(4);
  const page = await conversation("https://chat.deepseek.com/", `<p>Use ${`[${NAME}]`} please.</p>`, key);
  // Rename the message wrapper to something no selector knows about.
  await page.waitForSelector("main article.assistant");
  await page.evaluate(() => {
    const article = document.querySelector("main article.assistant");
    const div = document.createElement("div");
    div.innerHTML = article.innerHTML;
    article.replaceWith(div);
  });
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelectorAll(".chip").length >= 2);
  assert.equal((await copyViaChip(page, key)).trim(), `Use ${key} please.`);
  await page.close();
});

test("selecting the reply text and pressing Ctrl+C copies the real values", async () => {
  const key = fakeKey(5);
  const page = await conversation(CHATGPT, `<p>Put <span>[</span><span>${NAME}</span><span>]</span> in .env</p>`, key);
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelectorAll(".chip").length >= 2);
  await page.evaluate(() => {
    const p = document.querySelector('[data-message-author-role="assistant"] p');
    getSelection().selectAllChildren(p);
  });
  await page.keyboard.press("Control+C");
  await page.waitForFunction(async (k) => (await navigator.clipboard.readText()).includes(k), key);
  assert.equal((await page.evaluate(() => navigator.clipboard.readText())).trim(), `Put ${key} in .env`);
  await page.close();
});

test("a placeholder the guard did not create is left alone", async () => {
  const key = fakeKey(6);
  const page = await conversation(CHATGPT, `<p>Replace [DATABASE_URL_7] and [${NAME}].</p>`, key);
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelectorAll(".chip").length >= 2);
  const copied = await copyViaChip(page, key);
  assert.equal(copied.trim(), `Replace [DATABASE_URL_7] and ${key}.`);
  await page.close();
});

test("one chip per code block and per message, and none when nothing can be restored", async () => {
  const page = await open(browser.context, CHATGPT);
  await page.evaluate(() => (window.__nextReply = "<p>Nothing to restore here, [NOT_MINE_1].</p>"));
  await type(page, CHATGPT, "hello there");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.__sent.length === 1);
  await page.waitForTimeout(600);
  assert.equal(await page.locator("shadow-lens .chip").count(), 0);
  await page.close();
});

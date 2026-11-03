// The guard against a page that does not want it to work, and values that must not travel between sites.

import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import { choose, fakeKey, launch, open, panel, resetStorage, type, wait } from "./harness.mjs";

const CHATGPT = "https://chatgpt.com/";
let browser;

before(async () => {
  browser = await launch();
});
after(async () => browser?.close());
beforeEach(async () => resetStorage(browser.worker));

test("a value redacted on one site is never restored on another site in the same tab", async () => {
  const page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, `key ${fakeKey(1)}`);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  await choose(page, "Redact & send");
  await page.waitForFunction(() => window.__sent.length === 1);
  // Same tab, another AI site whose page happens to show the same placeholder.
  const other = "https://chat.deepseek.com/";
  await page.goto(other);
  await page.waitForFunction(() => typeof window.__editorText === "function");
  await page.evaluate(() => (window.__nextReply = "<p>Use [OPENAI_API_KEY_1] here.</p>"));
  await type(page, other, "hello");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelector("main article.assistant"));
  await wait(900);
  assert.equal(await page.locator("shadow-lens .chip").count(), 0, "no chip: this site has no vault entry");
  assert.equal(await page.evaluate(() => CSS.highlights.get("shadowlens-restorable")?.size ?? 0), 0);
  await page.close();
});

test("a page that hides or removes the guard cannot leave a message stuck or slip it through", async () => {
  const page = await open(browser.context, CHATGPT);
  await page.evaluate(() => {
    const style = document.createElement("style");
    style.textContent = "shadow-lens { display: none !important; visibility: hidden !important; opacity: 0 !important; }";
    document.head.append(style);
    document.querySelector("shadow-lens").remove();
  });
  await wait(100);
  assert.equal(await page.locator("shadow-lens").count(), 1, "the guard's host is put back");
  await type(page, CHATGPT, `key ${fakeKey(2)}`);
  await page.keyboard.press("Enter");
  await panel(page).waitFor({ state: "visible" });
  assert.deepEqual(await page.evaluate(() => window.__sent), []);
  await choose(page, "Edit message");
  await page.close();
});

test("the badge clears after a message is sent", async () => {
  const page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, `key ${fakeKey(3)}`);
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelector(".badge").textContent.includes("to review"));
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  await choose(page, "Redact & send");
  await page.waitForFunction(() => window.__sent.length === 1);
  await wait(1200);
  const badge = await page.evaluate(() => document.querySelector("shadow-lens").shadowRoot.querySelector(".badge").textContent);
  assert.ok(!badge.includes("to review"), `badge still says: ${badge}`);
  await page.close();
});

test("a plain textarea composer that the site's selectors do not name is still guarded", async () => {
  // Logged-out ChatGPT uses <textarea id="mobile-composer-prompt">: emulate an unknown textarea on chatgpt.com.
  const page = await open(browser.context, CHATGPT);
  await page.evaluate(() => {
    const form = document.querySelector("form");
    const box = document.createElement("textarea");
    box.placeholder = "Ask ChatGPT";
    box.style.width = "600px";
    const send = document.createElement("button");
    send.type = "button";
    send.setAttribute("aria-label", "Send message");
    send.textContent = "Send";
    send.onclick = () => window.__sent.push(box.value);
    form.replaceChildren(box, send);
  });
  await page.click("textarea");
  await page.keyboard.insertText(`deploy key ${fakeKey(4)}`);
  await page.locator("form button").click();
  await panel(page).waitFor();
  await choose(page, "Redact & send");
  await page.waitForFunction(() => window.__sent.length === 1);
  assert.deepEqual(await page.evaluate(() => window.__sent), ["deploy key [OPENAI_API_KEY_1]"]);
  await page.close();
});

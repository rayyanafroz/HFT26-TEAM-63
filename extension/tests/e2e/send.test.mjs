// Sending: clean messages pass untouched; messages with secrets are stopped, redacted or sent anyway.

import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import { choose, editorText, fakeKey, history as historyOf, launch, open, panel, resetStorage, sent, setPolicy, storage, type, wait } from "./harness.mjs";

const CHATGPT = "https://chatgpt.com/";
let browser;

before(async () => {
  browser = await launch();
});
after(async () => browser?.close());
beforeEach(async () => resetStorage(browser.worker));

test("a clean message is sent at once, with no panel", async () => {
  const page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, "How do I reverse a list in Python?");
  await wait(300); // the background check finishes while the person reads what they typed
  const started = Date.now();
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.__sent.length === 1);
  assert.ok(Date.now() - started < 300, "sending was not held up");
  assert.deepEqual(await sent(page), ["How do I reverse a list in Python?"]);
  assert.equal(await panel(page).count(), 0);
  await page.close();
});

test("a clean message sent before the background check finished still goes through", async () => {
  const page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, "What is a monad?");
  await page.keyboard.press("Enter"); // no pause: the guard checks, then sends it itself
  await page.waitForFunction(() => window.__sent.length === 1);
  assert.deepEqual(await sent(page), ["What is a monad?"]);
  await page.close();
});

test("a key is stopped; Redact & send sends a placeholder and the AI's answer can be copied with the real key", async () => {
  const page = await open(browser.context, CHATGPT);
  const key = fakeKey(1);
  await type(page, CHATGPT, `My script fails with OPENAI_API_KEY=${key} what is wrong?`);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  assert.match(await panel(page).innerText(), /stopped this message/);
  assert.match(await panel(page).innerText(), /OpenAI API key/);
  assert.ok(!(await panel(page).innerText()).includes(key), "the panel shows a mask, never the key");
  assert.deepEqual(await sent(page), [], "nothing reached the site");

  await choose(page, "Redact & send");
  await page.waitForFunction(() => window.__sent.length === 1);
  const [message] = await sent(page);
  assert.equal(message, "My script fails with OPENAI_API_KEY=[OPENAI_API_KEY_1] what is wrong?");

  // The reply mentions the placeholder: it is highlighted and a chip offers the real value.
  await page.waitForFunction(() => document.querySelector('[data-message-author-role="assistant"]'));
  const chip = page.locator("shadow-lens .chip");
  await chip.first().waitFor();
  assert.ok(await page.evaluate(() => CSS.highlights.get("shadowlens-restorable")?.size > 0));
  await chip.last().getByRole("button", { name: "Copy with real values" }).click();
  await page.waitForFunction(async (k) => (await navigator.clipboard.readText()).includes(k), key);
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  assert.ok(copied.includes(`export VALUE=${key}`));
  assert.ok(!(await page.evaluate(() => document.body.innerText)).includes(key), "the real key never enters the page");

  // The history keeps a mask, never the key, and nothing in storage holds it.
  await historyOf(browser.worker);
  const local = await storage(browser.worker);
  assert.equal(local.history[0].action, "redacted");
  assert.equal(local.history[0].findings[0].rule_id, "SEC_OPENAI_KEY");
  assert.match(local.history[0].findings[0].masked_preview, /^sk-p\.\.\. \(len \d+\)$/);
  assert.ok(!JSON.stringify(local).includes(key));
  await page.close();
});

test("the same key keeps its placeholder in a later message, and a second key gets the next number", async () => {
  const page = await open(browser.context, CHATGPT);
  for (const text of [`first ${fakeKey(1)}`, `again ${fakeKey(1)} and ${fakeKey(2)}`]) {
    await type(page, CHATGPT, text);
    await page.keyboard.press("Enter");
    await panel(page).waitFor();
    await choose(page, "Redact & send");
    await page.waitForFunction((n) => window.__sent.length === n, text.startsWith("first") ? 1 : 2);
  }
  assert.deepEqual(await sent(page), ["first [OPENAI_API_KEY_1]", "again [OPENAI_API_KEY_1] and [OPENAI_API_KEY_2]"]);
  await page.close();
});

test("Edit message keeps the text and sends nothing", async () => {
  const page = await open(browser.context, CHATGPT);
  const text = `token ${fakeKey(3)}`;
  await type(page, CHATGPT, text);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  await choose(page, "Edit message");
  await wait(200);
  assert.deepEqual(await sent(page), []);
  assert.equal(await editorText(page), text);
  const history = await historyOf(browser.worker);
  assert.equal(history[0].action, "cancelled");
  await page.close();
});

test("Send anyway needs a reason, which is kept in the history", async () => {
  const page = await open(browser.context, CHATGPT);
  const text = `use this test key ${fakeKey(4)}`;
  await type(page, CHATGPT, text);
  await page.click("#send");
  await panel(page).waitFor();
  await choose(page, "Send anyway…");
  const confirm = panel(page).getByRole("button", { name: "Send anyway", exact: true });
  assert.ok(await confirm.isDisabled(), "a reason is needed first");
  await panel(page).getByRole("textbox", { name: "Reason" }).fill("revoked test key");
  await confirm.click();
  await page.waitForFunction(() => window.__sent.length === 1);
  assert.deepEqual(await sent(page), [text]);
  const history = await historyOf(browser.worker);
  assert.equal(history[0].action, "sent_anyway");
  assert.equal(history[0].reason, "revoked test key");
  await page.close();
});

test("Not a secret: the value is remembered and goes through next time", async () => {
  const page = await open(browser.context, CHATGPT);
  const text = `password: Xk39aQ2zLm7pR`;
  await type(page, CHATGPT, text);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  await panel(page).getByRole("button", { name: "Not a secret" }).click();
  // Once every finding is dismissed the guard checks again and the message goes through.
  await page.waitForFunction(() => window.__sent.length === 1, null, { timeout: 5000 });
  assert.deepEqual(await sent(page), [text]);
  const { policy } = await storage(browser.worker);
  assert.equal(policy.allowlist.length, 1);
  assert.ok(!JSON.stringify(policy).includes("Xk39aQ2zLm7pR"));
  await page.close();
});

test("warn-only mode asks but needs no reason; off sends without asking", async () => {
  await setPolicy(browser.worker, { sites: { chatgpt: "warn" } });
  let page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, `k ${fakeKey(5)}`);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  assert.match(await panel(page).innerText(), /Check this message/);
  await choose(page, "Send anyway");
  await page.waitForFunction(() => window.__sent.length === 1);
  await page.close();

  await setPolicy(browser.worker, { sites: { chatgpt: "off" } });
  page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, `k ${fakeKey(6)}`);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.__sent.length === 1);
  assert.equal(await panel(page).count(), 0);
  await page.close();
});

test("the badge counts what is in the composer while typing", async () => {
  const page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, `mail jordan@acme-demo.invalid key ${fakeKey(7)}`);
  const badge = page.locator("shadow-lens .badge.show");
  await badge.waitFor();
  await page.waitForFunction(() => document.querySelector("shadow-lens").shadowRoot.querySelector(".badge").textContent.includes("2 to review"));
  await badge.click();
  await panel(page).waitFor();
  await choose(page, "Redact now");
  await page.waitForFunction(() => window.__editorText().includes("[OPENAI_API_KEY_1]"));
  assert.equal(await editorText(page), "mail [EMAIL_1] key [OPENAI_API_KEY_1]");
  assert.deepEqual(await sent(page), [], "redacting in place does not send");
  await page.close();
});

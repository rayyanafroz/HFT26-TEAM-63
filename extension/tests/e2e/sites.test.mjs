// The same guard on each kind of site: Claude (ProseMirror), Gemini (Quill), and a plain textarea.

import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import { choose, editorText, fakeKey, launch, open, panel, paste, resetStorage, sent, type, wait } from "./harness.mjs";

const SITES = ["https://claude.ai/", "https://gemini.google.com/", "https://chat.deepseek.com/"];
let browser;

before(async () => {
  browser = await launch();
});
after(async () => browser?.close());
beforeEach(async () => resetStorage(browser.worker));

for (const origin of SITES) {
  const host = new URL(origin).host;

  test(`${host}: a clean message goes straight through`, async () => {
    const page = await open(browser.context, origin);
    await type(page, origin, "Explain recursion simply");
    await wait(300);
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => window.__sent.length === 1);
    assert.deepEqual(await sent(page), ["Explain recursion simply"]);
    assert.equal(await panel(page).count(), 0);
    await page.close();
  });

  test(`${host}: a key is stopped and Redact & send sends the placeholder`, async () => {
    const page = await open(browser.context, origin);
    await type(page, origin, `deploy with GITHUB_TOKEN ${"gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"} please`);
    await page.keyboard.press("Enter");
    await panel(page).waitFor();
    assert.match(await panel(page).innerText(), /GitHub token/);
    assert.deepEqual(await sent(page), []);
    await choose(page, "Redact & send");
    await page.waitForFunction(() => window.__sent.length === 1);
    assert.deepEqual(await sent(page), ["deploy with GITHUB_TOKEN [GITHUB_TOKEN_1] please"]);
    // The reply echoes the placeholder: it can be copied back with the real value.
    const chip = page.locator("shadow-lens .chip");
    await chip.first().waitFor();
    await page.close();
  });

  test(`${host}: clicking the send button is guarded too`, async () => {
    const page = await open(browser.context, origin);
    await type(page, origin, `my card is 4111 1111 1111 1111`);
    await page.locator("#send").click();
    await panel(page).waitFor();
    await choose(page, "Redact & send");
    await page.waitForFunction(() => window.__sent.length === 1);
    assert.deepEqual(await sent(page), ["my card is [CARD_NUMBER_1]"]);
    await page.close();
  });

  test(`${host}: Paste redacted works in this editor`, async () => {
    const page = await open(browser.context, origin);
    const key = fakeKey(5);
    await paste(page, origin, `line one\nkey=${key}\nline three`);
    await panel(page).waitFor();
    await choose(page, "Paste redacted");
    await page.waitForFunction(() => window.__editorText().includes("[OPENAI_API_KEY_1]"));
    assert.equal(await editorText(page), "line one\nkey=[OPENAI_API_KEY_1]\nline three");
    assert.ok(!(await page.evaluate(() => document.body.innerHTML)).includes(key));
    await page.close();
  });

  test(`${host}: Shift+Enter makes a new line and is not a send`, async () => {
    const page = await open(browser.context, origin);
    await type(page, origin, `key ${fakeKey(6)}`);
    await page.keyboard.press("Shift+Enter");
    await wait(200);
    assert.equal(await panel(page).count(), 0);
    assert.deepEqual(await sent(page), []);
    await page.close();
  });
}

test("a 'Send feedback' button away from the composer is not treated as sending", async () => {
  const origin = "https://chat.deepseek.com/";
  const page = await open(browser.context, origin);
  await type(page, origin, `key ${fakeKey(7)}`);
  await page.locator("#feedback").click();
  await wait(200);
  assert.equal(await panel(page).count(), 0);
  assert.equal(await page.evaluate(() => window.__feedback), 1);
  assert.deepEqual(await sent(page), []);
  await page.close();
});

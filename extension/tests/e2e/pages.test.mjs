// The popup and options pages, live policy changes, and what is (not) kept.

import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import { choose, fakeKey, history as historyOf, launch, open, panel, paste, resetStorage, sent, setPolicy, storage, type, wait } from "./harness.mjs";

const CHATGPT = "https://chatgpt.com/";
let browser;
let base;

before(async () => {
  browser = await launch();
  base = browser.worker.url().split("/").slice(0, 3).join("/"); // URL.origin is "null" for chrome-extension:
});
after(async () => browser?.close());
beforeEach(async () => resetStorage(browser.worker));

async function stopOne(key) {
  const page = await open(browser.context, CHATGPT);
  await type(page, CHATGPT, `deploy key ${key}`);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  await choose(page, "Redact & send");
  await page.waitForFunction(() => window.__sent.length === 1);
  return page;
}

test("after a whole session no raw value is kept anywhere but the open tab's vault", async () => {
  const key = fakeKey(1);
  const page = await stopOne(key);
  await paste(page, CHATGPT, `card 4111 1111 1111 1111`);
  await panel(page).waitFor();
  await choose(page, "Paste redacted");
  await historyOf(browser.worker, 2);
  const local = JSON.stringify(await storage(browser.worker, "local"));
  assert.ok(!local.includes(key) && !local.includes("4111 1111 1111 1111"), "nothing raw in persistent storage");
  const session = await storage(browser.worker, "session");
  assert.ok(JSON.stringify(session).includes(key), "the tab's vault holds the value while the tab is open");
  await page.close();
  await wait(300);
  assert.deepEqual(await storage(browser.worker, "session"), {}, "closing the tab drops its vault");
});

test("changing the policy applies to an open tab at once", async () => {
  const page = await open(browser.context, CHATGPT);
  await setPolicy(browser.worker, { sites: { chatgpt: "off" } });
  await wait(300);
  await type(page, CHATGPT, `key ${fakeKey(2)}`);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.__sent.length === 1);
  assert.equal(await panel(page).count(), 0);
  await setPolicy(browser.worker, { sites: { chatgpt: "protect" } });
  await wait(300);
  await type(page, CHATGPT, `key ${fakeKey(3)}`);
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  assert.equal((await sent(page)).length, 1);
  await page.close();
});

test("the popup shows today's numbers and the latest events", async () => {
  (await stopOne(fakeKey(4))).close();
  await historyOf(browser.worker);
  const popup = await browser.context.newPage();
  await popup.goto(`${base}/popup/popup.html`);
  await popup.waitForFunction(() => document.getElementById("n-redacted").textContent === "1");
  assert.equal(await popup.locator("#n-stopped").innerText(), "1");
  assert.match(await popup.locator("#recent").innerText(), /Redacted/i);
  assert.match(await popup.locator("#recent").innerText(), /sk-p\.\.\./);
  await popup.close();
});

test("the options page: try text, change a site, see and clear the history", async () => {
  (await stopOne(fakeKey(5))).close();
  await historyOf(browser.worker);
  const options = await browser.context.newPage();
  await options.goto(`${base}/options/options.html`);
  await options.fill("#try-text", `export AWS_ACCESS_KEY_ID=${"AK" + "IA"}ABCDEFGHIJKLMNOP`);
  await options.locator("#try-result").getByText("AWS access key ID").waitFor();
  assert.match(await options.locator("#try-result").innerText(), /\[AWS_ACCESS_KEY_ID_1\]/);

  await options.locator("#sites tbody tr").filter({ hasText: "Claude" }).locator("select").selectOption("warn");
  await options.waitForFunction(async () => (await chrome.storage.local.get("policy")).policy?.sites?.claude === "warn");

  assert.match(await options.locator("#events").innerText(), /Redacted/i);
  options.once("dialog", (d) => d.accept());
  await options.click("#clear");
  await options.locator("#events").getByText("No events yet.").waitFor();
  await options.close();
});

test("the panel never shows a raw value, only masks", async () => {
  const page = await open(browser.context, CHATGPT);
  const values = [fakeKey(6), "4111 1111 1111 1111", "jordan.lee@acme-demo.invalid"];
  await type(page, CHATGPT, values.join(" and "));
  await page.keyboard.press("Enter");
  await panel(page).waitFor();
  const shown = await panel(page).innerText();
  for (const v of values) assert.ok(!shown.includes(v), `panel shows ${v}`);
  assert.match(shown, /\*\*\*\*1111/);
  assert.match(shown, /j\*\*\*@acme-demo\.invalid/);
  await page.close();
});

// Uploads: files are read and checked before the site sees them; clean ones pass, others are held.

import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import { docx, pdf } from "./documents.mjs";
import { choose, fakeKey, history as historyOf, launch, open, panel, resetStorage, uploads, wait } from "./harness.mjs";

const CHATGPT = "https://chatgpt.com/";
let browser;

before(async () => {
  browser = await launch();
});
after(async () => browser?.close());
beforeEach(async () => resetStorage(browser.worker));

const env = (key) => ({ name: ".env", mimeType: "", buffer: Buffer.from(`DEBUG=true\nOPENAI_API_KEY=${key}\nPORT=8080\n`) });

test("a clean file is uploaded at once", async () => {
  const page = await open(browser.context, CHATGPT);
  await page.setInputFiles("#upload", { name: "notes.md", mimeType: "text/markdown", buffer: Buffer.from("# Notes\nNothing secret here.\n") });
  await page.waitForFunction(() => window.__uploads.length === 1);
  assert.equal((await uploads(page))[0].name, "notes.md");
  assert.equal(await panel(page).count(), 0);
  await page.close();
});

test("a .env with a key is held; the redacted copy is what the site gets", async () => {
  const page = await open(browser.context, CHATGPT);
  const key = fakeKey(1);
  await page.setInputFiles("#upload", env(key));
  await panel(page).waitFor();
  assert.match(await panel(page).innerText(), /This file has something you should not share/);
  assert.match(await panel(page).innerText(), /\.env/);
  assert.deepEqual(await uploads(page), [], "the site has not seen the file");
  await choose(page, "Upload a redacted copy");
  await page.waitForFunction(() => window.__uploads.length === 1);
  const [file] = await uploads(page);
  assert.equal(file.name, ".env");
  assert.equal(file.text, "DEBUG=true\nOPENAI_API_KEY=[OPENAI_API_KEY_1]\nPORT=8080\n");
  await page.close();
});

test("Don't upload clears the file field and the site never sees the file", async () => {
  const page = await open(browser.context, CHATGPT);
  await page.setInputFiles("#upload", env(fakeKey(2)));
  await panel(page).waitFor();
  await choose(page, "Don't upload");
  await wait(150);
  assert.deepEqual(await uploads(page), []);
  assert.equal(await page.evaluate(() => document.getElementById("upload").files.length), 0);
  assert.equal((await historyOf(browser.worker))[0].action, "cancelled");
  await page.close();
});

test("Upload anyway sends the original, with the reason in the history", async () => {
  const page = await open(browser.context, CHATGPT);
  const key = fakeKey(3);
  await page.setInputFiles("#upload", env(key));
  await panel(page).waitFor();
  await choose(page, "Upload anyway…");
  await panel(page).getByRole("textbox", { name: "Reason" }).fill("key already revoked");
  await panel(page).getByRole("button", { name: "Upload anyway", exact: true }).click();
  await page.waitForFunction(() => window.__uploads.length === 1);
  assert.ok((await uploads(page))[0].text.includes(key));
  const [entry] = await historyOf(browser.worker);
  assert.equal(entry.action, "uploaded_anyway");
  assert.equal(entry.reason, "key already revoked");
  await page.close();
});

test("a PDF is read on this device; its redacted text is uploaded instead", async () => {
  const page = await open(browser.context, CHATGPT);
  const key = fakeKey(4);
  await page.setInputFiles("#upload", { name: "handover.pdf", mimeType: "application/pdf", buffer: pdf(["Production handover", `OPENAI_API_KEY=${key}`]) });
  await panel(page).waitFor({ timeout: 15000 });
  assert.match(await panel(page).innerText(), /handover\.pdf/);
  await choose(page, "Upload a redacted copy");
  await page.waitForFunction(() => window.__uploads.length === 1);
  const [file] = await uploads(page);
  assert.equal(file.name, "handover.pdf.redacted.txt");
  assert.ok(file.text.includes("OPENAI_API_KEY=[OPENAI_API_KEY_1]"));
  assert.ok(!file.text.includes(key));
  await page.close();
});

test("a Word document with a card number is caught", async () => {
  const page = await open(browser.context, CHATGPT);
  await page.setInputFiles("#upload", {
    name: "invoice.docx", mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    buffer: docx(["Invoice 42", "Card: 4111 1111 1111 1111", "Thanks"]),
  });
  await panel(page).waitFor({ timeout: 15000 });
  assert.match(await panel(page).innerText(), /Payment card number/);
  await choose(page, "Upload a redacted copy");
  await page.waitForFunction(() => window.__uploads.length === 1);
  assert.equal((await uploads(page))[0].text, "Invoice 42\nCard: [CARD_NUMBER_1]\nThanks");
  await page.close();
});

test("an image cannot be read: it goes through, and the person is told it was not checked", async () => {
  const page = await open(browser.context, CHATGPT);
  const png = Buffer.from("89504e470d0a1a0a0000000d4948445200000001000000010806000000", "hex");
  await page.setInputFiles("#upload", { name: "screenshot.png", mimeType: "image/png", buffer: png });
  await page.waitForFunction(() => window.__uploads.length === 1);
  await page.locator("shadow-lens .toast").filter({ hasText: "could not look inside: screenshot.png" }).waitFor();
  await page.close();
});

test("a file dropped on the page is checked before the site's drop handler", async () => {
  const page = await open(browser.context, CHATGPT);
  const key = fakeKey(5);
  await page.evaluate((k) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([`token=${k}\n`], "creds.txt", { type: "text/plain" }));
    document.getElementById("thread").dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: transfer }));
  }, key);
  await panel(page).waitFor();
  assert.deepEqual(await uploads(page), []);
  await choose(page, "Upload a redacted copy");
  await page.waitForFunction(() => window.__uploads.length === 1);
  const [file] = await uploads(page);
  assert.equal(file.how, "drop");
  assert.equal(file.text, "token=[OPENAI_API_KEY_1]\n");
  await page.close();
});

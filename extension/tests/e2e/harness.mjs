// End-to-end harness: real Chromium with the extension loaded (dist-test), and mock chat apps served on
// the real hosts (chatgpt.com, claude.ai, ...) so the content script runs exactly as it would there.

import * as esbuild from "esbuild";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

import { PAGES } from "./fixtures/pages.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const extension = join(here, "..", "..", "dist-test");

let bundles = null;
async function fixtureBundles() {
  if (bundles) return bundles;
  bundles = {};
  for (const name of ["prosemirror-chat.js", "quill-chat.js", "textarea-chat.js"]) {
    const result = await esbuild.build({ entryPoints: [join(here, "fixtures", name)], bundle: true, format: "esm", write: false, logLevel: "silent" });
    bundles[name] = result.outputFiles[0].text;
  }
  return bundles;
}

/** A fake key, built at run time (nothing token-shaped is committed). */
export function fakeKey(n = 1) {
  const body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v".split("");
  body[0] = String.fromCharCode(65 + n);
  return "sk-" + "proj-" + body.join("");
}

export async function launch() {
  const code = await fixtureBundles();
  const profile = mkdtempSync(join(tmpdir(), "shadowlens-e2e-"));
  const context = await chromium.launchPersistentContext(profile, {
    headless: true,
    // BROWSER=/usr/bin/brave (or any Chromium-based browser) runs the suite in that browser instead.
    ...(process.env.BROWSER ? { executablePath: process.env.BROWSER } : { channel: "chromium" }),
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
    permissions: ["clipboard-read", "clipboard-write"],
    viewport: { width: 1100, height: 900 },
  });
  for (const origin of Object.keys(PAGES)) {
    await context.route(`${origin}**`, (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.startsWith("/__fixture/")) {
        return route.fulfill({ contentType: "text/javascript", body: code[url.pathname.slice("/__fixture/".length)] });
      }
      return route.fulfill({ contentType: "text/html", body: PAGES[origin] });
    });
  }
  let [worker] = context.serviceWorkers();
  worker ??= await context.waitForEvent("serviceworker");
  return {
    context,
    worker,
    async close() {
      await context.close();
      rmSync(profile, { recursive: true, force: true });
    },
  };
}

/** Open a mock site and wait until the guard is running in it. */
export async function open(context, origin) {
  const page = await context.newPage();
  await page.goto(origin);
  await page.waitForFunction(() => typeof window.__editorText === "function");
  await page.waitForSelector("shadow-lens", { state: "attached" });
  return page;
}

export const COMPOSER = {
  "https://chatgpt.com/": "#prompt-textarea",
  "https://claude.ai/": "fieldset .ProseMirror",
  "https://gemini.google.com/": "rich-textarea .ql-editor",
  "https://chat.deepseek.com/": "#box",
};

export async function type(page, origin, text) {
  await page.click(COMPOSER[origin]);
  await page.keyboard.insertText(text);
}

/** Paste through the real clipboard (a trusted paste event, as when a person presses Ctrl+V). */
export async function paste(page, origin, text, html) {
  await page.click(COMPOSER[origin]);
  await page.evaluate(async ([t, h]) => {
    const items = { "text/plain": new Blob([t], { type: "text/plain" }) };
    if (h) items["text/html"] = new Blob([h], { type: "text/html" });
    await navigator.clipboard.write([new ClipboardItem(items)]);
  }, [text, html]);
  await page.keyboard.press("Control+V");
}

export const sent = (page) => page.evaluate(() => window.__sent);
export const uploads = (page) => page.evaluate(() => window.__uploads);
export const editorText = (page) => page.evaluate(() => window.__editorText());

/** The guard's panel, or null. */
export function panel(page) {
  return page.locator("shadow-lens .panel");
}

export async function choose(page, label) {
  await panel(page).getByRole("button", { name: label, exact: true }).click();
}

export async function storage(worker, area = "local") {
  return worker.evaluate((a) => chrome.storage[a].get(null), area);
}

/** The history once it has at least `n` entries (events are written just after the action). */
export async function history(worker, n = 1) {
  for (let i = 0; i < 50; i++) {
    const { history = [] } = await storage(worker);
    if (history.length >= n) return history;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`the history never reached ${n} entries`);
}

export async function setPolicy(worker, change) {
  await worker.evaluate(async (c) => {
    const { policy = {} } = await chrome.storage.local.get("policy");
    await chrome.storage.local.set({ policy: { ...policy, ...c } });
  }, change);
}

export async function resetStorage(worker) {
  await worker.evaluate(async () => {
    const { salt } = await chrome.storage.local.get("salt");
    await chrome.storage.local.clear();
    await chrome.storage.session.clear();
    await chrome.storage.local.set({ salt });
  });
}

export const wait = (ms) => new Promise((r) => setTimeout(r, ms));

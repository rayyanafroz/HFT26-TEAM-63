// The extension's background: runs the engine, applies the policy, keeps the vault and the history.
//
// Content scripts on the AI sites ask it to scan text and to redact it; the popup and the options page
// read and change the policy and the history. Nothing here talks to the network: the engine is a local
// WebAssembly module, and the only other endpoint is the optional desktop companion (Native Messaging).

import { loadEngine } from "../engine/engine.js";
import { clean, inspect } from "../shared/injection.js";
import { knownPlaceholders, redact, restore } from "../shared/placeholders.js";
import { decide, isAllowlisted, siteMode } from "../shared/policy.js";
import { ruleInfo } from "../shared/rules.js";
import { SITES, matchPatterns, siteForHost } from "../shared/sites.js";
import * as companion from "./companion.js";
import * as store from "./store.js";

const MAX_TEXT = 5 * 1024 * 1024; // characters; bigger text is not checked (and the person is told)
const MAX_DOCUMENT_BASE64 = 30 * 1024 * 1024; // a 20 MB screenshot is about 27 MB of base64

const hostOf = (sender) => new URL(sender.url ?? sender.tab?.url ?? "about:blank").host;

let engine = null; // { key, promise }

async function getEngine() {
  const [policy, salt] = await Promise.all([store.getPolicy(), store.getSalt()]);
  // No entropy cap here: every finding is listed, so every one can be replaced by a placeholder.
  const settings = { salt_hex: salt, max_entropy_findings_per_event: 100000, ...policy.engine };
  const key = JSON.stringify(settings);
  if (!engine || engine.key !== key) {
    const promise = loadEngine(chrome.runtime.getURL("engine/shadowlens_engine.wasm"), settings);
    engine = { key, promise };
    promise.catch(() => {
      if (engine?.promise === promise) engine = null; // try again next time
    });
  }
  return engine.promise;
}

/** Engine findings plus what a person needs to read them. */
function enrich(f) {
  const info = ruleInfo(f.rule_id);
  return {
    ...f,
    title: info.title,
    severity: f.severity ?? info.severity,
    kind: info.kind,
    redactable: info.redactable,
    placeholder: info.placeholder,
    why: info.why,
    fix: info.fix,
  };
}

async function scan(text, kind, siteId) {
  const policy = await store.getPolicy();
  const mode = siteMode(policy, siteId);
  const base = { mode, requireReason: policy.requireReason, allowOverride: policy.allowOverride };
  if (mode === "off") return { ...base, enabled: false, findings: [], decision: { action: "allow", severity: "none", mode }, failed: [] };
  if (text.length > MAX_TEXT) {
    return { ...base, enabled: true, tooLarge: true, findings: [], failed: ["size"], decision: { action: "warn", severity: "none", mode } };
  }
  const result = (await getEngine()).analyze(text);
  const findings = result.findings.map(enrich).filter((f) => !isAllowlisted(policy, f));
  if (policy.hiddenText) findings.push(...inspect(text).map(enrich));
  const decision = decide(findings, policy, siteId);
  // A detector that could not run means the text was not fully checked: never let that pass silently.
  if (result.failed.length && decision.action !== "block") decision.action = "warn";
  return { ...base, enabled: true, findings, decision, failed: result.failed };
}

async function record(event, sender) {
  const site = event.site ?? siteForHost(new URL(sender.tab?.url ?? sender.url ?? "about:blank").host)?.id;
  const entry = await store.addHistory({ ...event, site });
  const policy = await store.getPolicy();
  if (policy.companion) companion.sendEvent(entry);
  return entry;
}

function badge(tabId, result) {
  if (tabId == null) return;
  const count = result.findings?.length ?? 0;
  const action = result.decision?.action;
  chrome.action.setBadgeText({ tabId, text: count ? String(count) : "" }).catch(() => {});
  chrome.action
    .setBadgeBackgroundColor({ tabId, color: action === "block" ? "#B3261E" : action === "warn" ? "#8F5300" : "#0B7A75" })
    .catch(() => {});
}

// PDF and Office files are read in an offscreen page, which can run pdf.js with its worker.
let offscreenReady = null;
function ensureOffscreen() {
  offscreenReady ??= (async () => {
    const existing = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    if (existing.length) return;
    await chrome.offscreen.createDocument({
      url: "offscreen/offscreen.html",
      reasons: ["WORKERS"],
      justification: "Read the text of PDF and Office files on this device, to check them for secrets before upload.",
    });
  })().catch((error) => {
    offscreenReady = null;
    throw error;
  });
  return offscreenReady;
}

async function extractDocument(name, base64) {
  await ensureOffscreen();
  const reply = await chrome.runtime.sendMessage({ target: "offscreen", name, base64 });
  if (reply?.error) throw new Error(reply.error);
  return reply?.text ?? null;
}

// Extension pages (popup, options; the options page opens in a tab) live at the extension's origin;
// content scripts report the URL of the site they run in.
const fromExtensionPage = (sender) => sender.id === chrome.runtime.id && !!sender.url?.startsWith(chrome.runtime.getURL(""));
const fromOurContentScript = (sender) => {
  if (sender.id !== chrome.runtime.id || !sender.tab || fromExtensionPage(sender)) return false;
  try {
    return !!siteForHost(new URL(sender.url ?? sender.tab.url).host);
  } catch {
    return false;
  }
};

const handlers = {
  // ---- content scripts ----
  async scan({ text, kind, site }, sender) {
    const result = await scan(String(text ?? ""), kind, site);
    if (kind === "typing") badge(sender.tab?.id, result);
    return result;
  },
  async redact({ text, kind, site, cleanHidden }, sender) {
    text = String(text ?? "");
    const result = await scan(text, kind, site);
    return store.withVault(sender.tab.id, hostOf(sender), (vault) => {
      const out = redact(text, result.findings, vault);
      return {
        text: cleanHidden ? clean(out.text) : out.text,
        replaced: out.replaced,
        remaining: result.findings.filter((f) => !f.redactable),
      };
    });
  },
  async restore({ text }, sender) {
    if (String(text ?? "").length > MAX_TEXT) throw new Error("too much text to restore");
    const vault = await store.getVault(sender.tab.id, hostOf(sender));
    return { text: restore(String(text ?? ""), vault), placeholders: knownPlaceholders(String(text ?? ""), vault) };
  },
  async vaultNames(_, sender) {
    const vault = await store.getVault(sender.tab.id, hostOf(sender));
    return { names: Object.keys(vault.values) };
  },
  async extract({ name, base64 }) {
    if (String(base64 ?? "").length > MAX_DOCUMENT_BASE64) throw new Error("the file is too large to read");
    return { text: await extractDocument(String(name).slice(0, 255), String(base64)) };
  },
  async record({ event }, sender) {
    return record(event, sender);
  },
  async notASecret({ finding }) {
    const policy = await store.updatePolicy((p) => {
      if (!isAllowlisted(p, finding)) {
        p.allowlist.push({ rule_id: finding.rule_id, hash12: finding.hash12, masked_preview: finding.masked_preview, added: Date.now() });
      }
      return p;
    });
    return { allowlist: policy.allowlist.length };
  },
  async config({ site }) {
    const policy = await store.getPolicy();
    return {
      mode: siteMode(policy, site),
      scanPaste: policy.scanPaste,
      scanFiles: policy.scanFiles,
      maxFileBytes: policy.maxFileMB * 1024 * 1024,
      requireReason: policy.requireReason,
      allowOverride: policy.allowOverride,
    };
  },

  // ---- popup and options page ----
  async getState() {
    const [policy, stats, history] = await Promise.all([store.getPolicy(), store.getStats(), store.getHistory(20)]);
    return { policy, stats, history, sites: SITES };
  },
  async setPolicy({ change }) {
    return { policy: await store.updatePolicy(change) };
  },
  async getHistory({ limit }) {
    return { history: await store.getHistory(limit) };
  },
  async clearHistory() {
    await store.clearHistory();
    return { ok: true };
  },
  async companionStatus() {
    return companion.status();
  },
  async tryText({ text }) {
    const result = await scan(String(text ?? ""), "paste", SITES[0].id);
    return result;
  },
};

const pageOnly = new Set(["getState", "setPolicy", "getHistory", "clearHistory", "companionStatus", "tryText"]);

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.target === "offscreen") return false; // for the offscreen page, not for us
  const handler = handlers[message?.type];
  if (!handler) return false;
  const allowed = pageOnly.has(message.type) ? fromExtensionPage(sender) : fromOurContentScript(sender) || fromExtensionPage(sender);
  if (!allowed) {
    reply({ error: "not allowed" });
    return false;
  }
  handler(message, sender).then(
    (result) => reply(result),
    (error) => reply({ error: String(error?.message ?? error) }),
  );
  return true; // the reply is asynchronous
});

chrome.tabs.onRemoved.addListener((tabId) => {
  store.dropVaults(tabId);
});

// Tabs that were open before an install or update have no content script; put one in.
chrome.runtime.onInstalled.addListener(async () => {
  await store.getSalt();
  const tabs = await chrome.tabs.query({ url: matchPatterns() });
  for (const tab of tabs) {
    chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: ["content/content.css"] }).catch(() => {});
    chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content/content.js"] }).catch(() => {});
  }
});

// Load the engine early so the first check is fast.
getEngine().catch(() => {});

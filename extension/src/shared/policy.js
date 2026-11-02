// The guard's policy: what happens for each severity, per site, and the decision for one set of findings.

import { RULES, ruleInfo, severityRank } from "./rules.js";
import { SITES } from "./sites.js";

export const ACTIONS = ["allow", "note", "warn", "block"];

export const DEFAULT_POLICY = Object.freeze({
  enabled: true,
  // protect: the actions below; warn: never block, only warn; off: do nothing on that site.
  sites: Object.fromEntries(SITES.map((s) => [s.id, "protect"])),
  actions: { critical: "block", high: "block", medium: "warn", low: "note" },
  allowOverride: true, // "Send anyway" is offered for blocked messages
  requireReason: true, // and needs a short reason, kept in the local history
  scanPaste: true,
  scanFiles: true,
  hiddenText: true,
  companion: true, // also send guard events to the desktop companion when it is installed
  maxFileMB: 5,
  engine: { email_skip_domains: ["example.com", "example.org", "test.com", "localhost"], internal_markers: [] },
  allowlist: [], // [{ rule_id, hash12, masked_preview, added }]: values the person said are not secrets
});

function isObject(v) {
  return v && typeof v === "object" && !Array.isArray(v);
}

/** Stored settings on top of the defaults; unknown keys are dropped and bad values fall back. */
export function mergePolicy(stored) {
  const p = structuredClone(DEFAULT_POLICY);
  if (!isObject(stored)) return p;
  for (const key of ["enabled", "allowOverride", "requireReason", "scanPaste", "scanFiles", "hiddenText", "companion"]) {
    if (typeof stored[key] === "boolean") p[key] = stored[key];
  }
  if (Number.isFinite(stored.maxFileMB) && stored.maxFileMB > 0 && stored.maxFileMB <= 50) p.maxFileMB = stored.maxFileMB;
  if (isObject(stored.sites)) {
    for (const [id, mode] of Object.entries(stored.sites)) {
      if (id in p.sites && ["protect", "warn", "off"].includes(mode)) p.sites[id] = mode;
    }
  }
  if (isObject(stored.actions)) {
    for (const [sev, action] of Object.entries(stored.actions)) {
      if (sev in p.actions && ACTIONS.includes(action)) p.actions[sev] = action;
    }
  }
  if (isObject(stored.engine)) {
    for (const key of ["email_skip_domains", "internal_markers"]) {
      const list = stored.engine[key];
      if (Array.isArray(list)) p.engine[key] = list.filter((s) => typeof s === "string" && s.trim()).map((s) => s.trim()).slice(0, 200);
    }
  }
  if (Array.isArray(stored.allowlist)) {
    p.allowlist = stored.allowlist
      .filter((e) => isObject(e) && typeof e.rule_id === "string" && /^[0-9a-f]{12}$/.test(e.hash12))
      .slice(0, 1000);
  }
  return p;
}

export function siteMode(policy, siteId) {
  if (!policy.enabled) return "off";
  return policy.sites[siteId] ?? "protect";
}

export function isAllowlisted(policy, finding) {
  return policy.allowlist.some((e) => e.rule_id === finding.rule_id && e.hash12 === finding.hash12);
}

/**
 * What to do with these findings on this site: "allow" (nothing found), "note" (show quietly),
 * "warn" (stop and ask, sending anyway is one click) or "block" (stop; sending anyway may need a reason).
 */
export function decide(findings, policy, siteId) {
  const mode = siteMode(policy, siteId);
  if (mode === "off" || findings.length === 0) return { action: "allow", severity: "none", mode };
  let top = "low";
  for (const f of findings) {
    const severity = f.severity ?? ruleInfo(f.rule_id).severity;
    if (severityRank(severity) > severityRank(top)) top = severity;
  }
  let action = "note";
  for (const f of findings) {
    const a = policy.actions[f.severity ?? ruleInfo(f.rule_id).severity] ?? "warn";
    if (ACTIONS.indexOf(a) > ACTIONS.indexOf(action)) action = a;
  }
  if (mode === "warn" && action === "block") action = "warn";
  return { action, severity: top, mode };
}

export { RULES };

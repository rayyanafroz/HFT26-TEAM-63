// The AI chat sites the guard runs on. `adapter` names the code that knows each site's composer
// (src/content/adapters.js); "generic" works from common patterns and is best effort.

export const SITES = [
  { id: "chatgpt", name: "ChatGPT", hosts: ["chatgpt.com", "chat.openai.com"], adapter: "chatgpt" },
  { id: "claude", name: "Claude", hosts: ["claude.ai"], adapter: "claude" },
  { id: "gemini", name: "Gemini", hosts: ["gemini.google.com"], adapter: "gemini" },
  { id: "copilot", name: "Microsoft Copilot", hosts: ["copilot.microsoft.com"], adapter: "generic" },
  { id: "perplexity", name: "Perplexity", hosts: ["www.perplexity.ai", "perplexity.ai"], adapter: "generic" },
  { id: "deepseek", name: "DeepSeek", hosts: ["chat.deepseek.com"], adapter: "generic" },
  { id: "mistral", name: "Mistral Le Chat", hosts: ["chat.mistral.ai"], adapter: "generic" },
];

export function siteForHost(host) {
  return SITES.find((s) => s.hosts.includes(host)) ?? null;
}

/** Match patterns for the manifest and for re-injecting into open tabs. */
export function matchPatterns() {
  return SITES.flatMap((s) => s.hosts.map((h) => `https://${h}/*`));
}

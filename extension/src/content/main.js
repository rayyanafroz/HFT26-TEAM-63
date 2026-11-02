// Shadow Lens on an AI chat site: starts the guard and the placeholder restorer.

import { siteForHost } from "../shared/sites.js";
import { createAdapter } from "./adapters.js";
import { createGuard } from "./guard.js";
import { createRestore } from "./restore.js";
import { createUI } from "./ui.js";

(async () => {
  const site = siteForHost(location.host);
  if (!site) return;

  // After an update, the new copy of this script is injected next to the old one: the old one stops.
  // Both run in the extension's isolated world, which the page cannot reach, so the hand-over is a global
  // there and not a DOM event (the site could send one of those to switch the guard off).
  globalThis.__shadowLensStop?.();

  let stopped = false;
  let ui = null;
  let guard = null;
  let restorer = null;

  function stop() {
    if (stopped) return;
    stopped = true;
    guard?.detach();
    restorer?.stop();
    ui?.destroy();
  }
  globalThis.__shadowLensStop = stop;

  async function send(type, payload = {}) {
    if (stopped) throw new Error("Shadow Lens was updated; reload the page");
    let reply;
    try {
      reply = await chrome.runtime.sendMessage({ type, ...payload });
    } catch (error) {
      if (/context invalidated|receiving end does not exist/i.test(String(error?.message))) stop();
      throw error;
    }
    if (reply?.error) throw new Error(reply.error);
    return reply;
  }

  let config;
  try {
    config = await send("config", { site: site.id });
  } catch {
    return; // the extension is reloading; the new copy will take over
  }

  ui = createUI();
  const adapter = createAdapter(site.adapter);
  restorer = createRestore({ adapter, ui, send });
  const sendAndRefresh = async (type, payload) => {
    const reply = await send(type, payload);
    if (type === "redact") restorer.refreshNames();
    return reply;
  };
  guard = createGuard({ adapter, ui, send: sendAndRefresh, site, config });
  guard.attach();
  restorer.start();

  chrome.storage.onChanged.addListener(async (changes, area) => {
    if (area !== "local" || !changes.policy || stopped) return;
    try {
      guard.setConfig(await send("config", { site: site.id }));
    } catch {
      /* stopped */
    }
  });
})();

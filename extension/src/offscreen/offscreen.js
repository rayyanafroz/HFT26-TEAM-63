// The offscreen page: answers the service worker's requests to read documents.

import { extract } from "./extract.js";

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.target !== "offscreen" || sender.id !== chrome.runtime.id) return false; // not for this page
  extract(message.name, message.base64).then(
    (text) => reply({ text }),
    (error) => reply({ error: String(error?.message ?? error) }),
  );
  return true;
});

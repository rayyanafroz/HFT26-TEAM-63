// A chat composer on Quill inside <rich-textarea>, shaped like Gemini's.

import Quill from "quill/core";
import { el, record, replyInto, watchFiles } from "./common.js";

customElements.define("rich-textarea", class extends HTMLElement {});
customElements.define("user-query", class extends HTMLElement {});
customElements.define("model-response", class extends HTMLElement {});

const thread = document.getElementById("thread");
const button = document.getElementById("send");
const quill = new Quill(document.querySelector("rich-textarea > div"), {
  modules: { keyboard: { bindings: { send: { key: "Enter", shiftKey: false, handler: () => (send(), false) } } } },
});

function send() {
  const message = quill.getText().trim();
  if (!message) return;
  record(message);
  thread.append(el("user-query", {}, message));
  setTimeout(() => {
    const box = el("model-response");
    replyInto(box, message);
    thread.append(box);
  }, 30);
  quill.setText("");
}
quill.on("text-change", () => (button.disabled = !quill.getText().trim()));
button.disabled = true;
button.addEventListener("click", send);
watchFiles(document.getElementById("upload"));
window.__editorText = () => quill.getText().replace(/\n$/, "");

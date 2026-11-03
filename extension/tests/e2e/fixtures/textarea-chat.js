// A plain <textarea> chat, for the generic adapter (DeepSeek, Perplexity and the like).

import { el, record, replyInto, watchFiles } from "./common.js";

const thread = document.getElementById("thread");
const box = document.getElementById("box");
const button = document.getElementById("send");

function send() {
  const message = box.value.trim();
  if (!message) return;
  record(message);
  thread.append(el("article", { class: "message user" }, message));
  setTimeout(() => {
    const box = el("article", { class: "message assistant" });
    replyInto(box, message);
    thread.append(box);
  }, 30);
  box.value = "";
}
box.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    send();
  }
});
button.addEventListener("click", send);
window.__feedback = 0;
document.getElementById("feedback").addEventListener("click", () => window.__feedback++);
watchFiles(document.getElementById("upload"));
window.__editorText = () => box.value;

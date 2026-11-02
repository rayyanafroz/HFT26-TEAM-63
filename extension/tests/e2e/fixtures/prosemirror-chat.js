// A chat composer on ProseMirror, shaped like ChatGPT's or Claude's (chosen by window.__variant).

import { EditorState } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { schema } from "prosemirror-schema-basic";
import { keymap } from "prosemirror-keymap";
import { baseKeymap, chainCommands, exitCode } from "prosemirror-commands";
import { el, record, reply, watchFiles } from "./common.js";

const claude = window.__variant === "claude";
const thread = document.getElementById("thread");
const mount = document.getElementById("composer");
const button = document.getElementById("send");

function text(state) {
  return state.doc.textBetween(0, state.doc.content.size, "\n", "\n");
}

function send() {
  const message = text(view.state).trim();
  if (!message) return true;
  record(message);
  const user = claude ? el("div", { "data-testid": "user-message" }, message) : el("div", { "data-message-author-role": "user" }, message);
  thread.append(user);
  setTimeout(() => {
    const answer = reply(message);
    thread.append(claude ? el("div", { class: "font-claude-response" }, answer) : el("div", { "data-message-author-role": "assistant" }, answer));
  }, 30);
  view.dispatch(view.state.tr.delete(0, view.state.doc.content.size));
  return true;
}

const hardBreak = chainCommands(exitCode, (state, dispatch) => {
  dispatch(state.tr.replaceSelectionWith(schema.nodes.hard_break.create()).scrollIntoView());
  return true;
});

const view = new EditorView(mount, {
  state: EditorState.create({ schema, plugins: [keymap({ Enter: send, "Shift-Enter": baseKeymap.Enter, "Mod-Enter": hardBreak }), keymap(baseKeymap)] }),
  attributes: claude ? { class: "ProseMirror" } : { id: "prompt-textarea", class: "ProseMirror" },
  dispatchTransaction(tr) {
    view.updateState(view.state.apply(tr));
    button.disabled = !text(view.state).trim();
  },
});
button.disabled = true;
button.addEventListener("click", send);
watchFiles(document.getElementById("upload"));
window.__editorText = () => text(view.state);

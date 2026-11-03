// Shared by the mock chat apps: what the "AI provider" receives, and a reply that echoes placeholders the
// way a real model does ("Set [OPENAI_API_KEY_1] in your environment").

window.__sent = [];
window.__uploads = [];

export function reply(text) {
  const tokens = [...new Set(text.match(/\[[A-Z][A-Z0-9_]*_\d+\]/g) ?? [])];
  return tokens.length
    ? `Thanks. Put ${tokens.join(" and ")} in your environment, not in the code. For example: export VALUE=${tokens[0]}`
    : "Thanks, here is my answer.";
}

/**
 * A reply as real chat apps render it: a paragraph whose words are each in their own <span> (streaming
 * animation), and a syntax-highlighted code block where the placeholder is split into three spans.
 */
export function replyInto(parent, text) {
  if (window.__nextReply != null) {        // a test supplies the exact HTML a chat app might render
    parent.innerHTML = window.__nextReply;
    window.__nextReply = null;
    return;
  }
  const tokens = [...new Set(text.match(/\[[A-Z][A-Z0-9_]*_\d+\]/g) ?? [])];
  if (!tokens.length) {
    parent.append(el("p", {}, "Thanks, here is my answer."));
    return;
  }
  const p = el("p");
  for (const word of `Thanks. Put ${tokens.join(" and ")} in your environment, not in the code. For example:`.split(" ")) {
    p.append(el("span", {}, word), document.createTextNode(" "));
  }
  const code = el("code", { class: "hljs" });
  code.append(el("span", { class: "hljs-keyword" }, "export"), document.createTextNode(" VALUE="));
  const name = tokens[0].slice(1, -1);
  code.append(el("span", { class: "hljs-punct" }, "["), el("span", { class: "hljs-var" }, name), el("span", { class: "hljs-punct" }, "]"));
  const pre = el("pre");
  pre.append(code);
  parent.append(p, pre);
}

export function record(text) {
  window.__sent.push(text);
}

export function watchFiles(input, area) {
  const take = async (files, how) => {
    for (const f of files) window.__uploads.push({ name: f.name, type: f.type, text: await f.text(), how });
  };
  input?.addEventListener("change", () => take([...input.files], "input"));
  (area ?? document).addEventListener("dragover", (e) => e.preventDefault());
  (area ?? document).addEventListener("drop", (e) => {
    e.preventDefault();
    take([...e.dataTransfer.files], "drop");
  });
}

export function el(tag, attrs = {}, text = "") {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text) node.textContent = text;
  return node;
}

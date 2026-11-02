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

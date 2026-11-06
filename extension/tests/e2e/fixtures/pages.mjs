// The HTML of each mock site. Served by Playwright on the real hosts, so the extension runs as it would there.

const shell = (title, body, script, variant = "") => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:15px system-ui;margin:0;padding:20px;max-width:760px} #thread{min-height:200px} #thread>*{padding:8px;margin:6px 0;border-radius:6px;background:#f2f2f2}
.ProseMirror,.ql-editor,textarea{min-height:60px;border:1px solid #999;padding:8px;white-space:pre-wrap;outline:none;width:100%;box-sizing:border-box}
.ql-editor p{margin:0} form,fieldset{border:0;padding:0;margin:12px 0}</style></head>
<body><main><div id="thread"></div>${body}</main>
<script>window.__variant=${JSON.stringify(variant)}</script><script type="module" src="/__fixture/${script}"></script></body></html>`;

export const PAGES = {
  "https://chatgpt.com/": shell("ChatGPT", `<form onsubmit="return false"><div id="composer"></div>
    <button type="button" id="send" data-testid="send-button" aria-label="Send prompt">&uarr;</button>
    <input type="file" id="upload" multiple></form>`, "prosemirror-chat.js", "chatgpt"),
  "https://claude.ai/": shell("Claude", `<fieldset><div id="composer"></div>
    <button type="button" id="send" aria-label="Send message">Send</button>
    <input type="file" id="upload" data-testid="file-upload" multiple></fieldset>`, "prosemirror-chat.js", "claude"),
  "https://gemini.google.com/": shell("Gemini", `<div class="input-area"><rich-textarea><div></div></rich-textarea>
    <button type="button" id="send" class="send-button" aria-label="Send message">Send</button>
    <input type="file" id="upload" multiple></div>`, "quill-chat.js"),
  "https://chat.deepseek.com/": shell("DeepSeek", `<div class="composer"><textarea id="box" placeholder="Message"></textarea>
    <div role="button" id="send" aria-label="Send" tabindex="0"><button type="button" aria-label="Send">Send</button></div>
    <input type="file" id="upload" multiple></div>
    <footer style="margin-top:200px"><button type="button" id="feedback" aria-label="Send feedback">Send feedback</button></footer>`, "textarea-chat.js"),
};

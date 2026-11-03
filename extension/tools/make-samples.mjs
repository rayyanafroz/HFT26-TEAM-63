// Writes sample files with FAKE secrets into extension/samples/, for trying the guard by hand:
// drag them into ChatGPT, Claude or Gemini, or paste the screenshots.
//   node tools/make-samples.mjs

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

import { docx, pdf } from "../tests/e2e/documents.mjs";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "samples");
mkdirSync(out, { recursive: true });

// Fake values, put together here so no key-shaped text sits in the source.
const key = "sk-" + "proj-" + "9fK2mQ7xLw0Zr4Tb6Yn1Vc8Hd3Jg5Pa2Se4Ui7Oy";
const aws = "AK" + "IA" + "Q7W3E9R2T5Y1U8I4";
const gh = "gh" + "p_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";

const files = {
  ".env": `DEBUG=false\nPORT=8080\nDATABASE_URL=postgres://app:S3cretPassw0rd@db.internal:5432/prod\nAWS_ACCESS_KEY_ID=${aws}\nOPENAI_API_KEY=${key}\n`,
  "config.py": `import os\n\nGITHUB_TOKEN = "${gh}"\nDEBUG = os.environ.get("DEBUG", "0")\n`,
  "handover.pdf": pdf(["Production handover notes", "", `OPENAI_API_KEY=${key}`, "Deploy with: make release", "On-call: jordan.lee@acme-demo.invalid"]),
  "invoice.docx": docx(["Invoice 2026-114", "Card on file: 4111 1111 1111 1111", "Customer: Jordan Lee", "SSN: 078-05-1120", "Thanks for your business."]),
  "notes.md": "# Meeting notes\n\nShip the landing page on Friday.\nNothing sensitive in this file; it should upload without a panel.\n",
};
for (const [name, body] of Object.entries(files)) writeFileSync(join(out, name), body);

// Screenshots, drawn the way a terminal or a spreadsheet would show them.
const browser = await chromium.launch({ channel: "chromium" });
const page = await browser.newPage();
const shots = {
  "screenshot-env.png": [".env", "DEBUG=false", `OPENAI_API_KEY=${key}`, "PORT=8080"],
  "screenshot-card.png": ["Invoice 2026-114", "Card: 4111 1111 1111 1111", "SSN: 078-05-1120", "Thank you"],
  "screenshot-clean.png": ["Meeting notes", "Ship the landing page on Friday"],
};
for (const [name, lines] of Object.entries(shots)) {
  const dataUrl = await page.evaluate((rows) => {
    const canvas = document.createElement("canvas");
    canvas.width = 80 + 18 * Math.max(...rows.map((r) => r.length));
    canvas.height = 60 + rows.length * 50;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#101820";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#f2f2f2";
    ctx.font = "30px monospace";
    rows.forEach((row, i) => ctx.fillText(row, 30, 60 + i * 50));
    return canvas.toDataURL("image/png");
  }, lines);
  writeFileSync(join(out, name), Buffer.from(dataUrl.split(",")[1], "base64"));
}
await browser.close();
console.log(`wrote ${Object.keys(files).length + Object.keys(shots).length} files to ${out}`);

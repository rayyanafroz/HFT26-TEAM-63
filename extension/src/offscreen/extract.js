// Text out of PDF and Office documents, on this device. Runs in the extension's offscreen page.

import * as pdfjs from "pdfjs-dist";
import { unzipSync, strFromU8 } from "fflate";

pdfjs.GlobalWorkerOptions.workerSrc = new URL("pdf.worker.min.mjs", import.meta.url).href;

const MAX_PAGES = 300;

async function pdfText(bytes) {
  const task = pdfjs.getDocument({ data: bytes, isEvalSupported: false, disableFontFace: true, useSystemFonts: false });
  const doc = await task.promise;
  const pages = [];
  for (let n = 1; n <= Math.min(doc.numPages, MAX_PAGES); n++) {
    const page = await doc.getPage(n);
    const content = await page.getTextContent();
    let line = "";
    const lines = [];
    for (const item of content.items) {
      line += item.str ?? "";
      if (item.hasEOL) {
        lines.push(line);
        line = "";
      }
    }
    if (line) lines.push(line);
    pages.push(lines.join("\n"));
  }
  await task.destroy(); // pdf.js 6 cleans up through the loading task
  return pages.join("\n\n");
}

/** Text of XML parts: each element named in `blocks` ends a line; text comes from `texts` elements. */
function xmlText(xml, texts, blocks) {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const lines = [];
  for (const block of doc.getElementsByTagName(blocks)) {
    const parts = [...block.getElementsByTagName(texts)].map((t) => t.textContent);
    if (parts.length) lines.push(parts.join(""));
  }
  if (!lines.length) lines.push(...[...doc.getElementsByTagName(texts)].map((t) => t.textContent));
  return lines.join("\n");
}

function officeText(name, bytes) {
  const zip = unzipSync(bytes, { filter: (f) => /\.xml$/.test(f.name) && f.originalSize < 50 * 1024 * 1024 });
  const parts = (re) => Object.keys(zip).filter((p) => re.test(p)).sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
  const read = (p) => strFromU8(zip[p]);
  if (/\.docx$/i.test(name)) {
    return parts(/^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/).map((p) => xmlText(read(p), "w:t", "w:p")).join("\n");
  }
  if (/\.pptx$/i.test(name)) {
    return parts(/^ppt\/(slides\/slide|notesSlides\/notesSlide)\d+\.xml$/).map((p) => xmlText(read(p), "a:t", "a:p")).join("\n\n");
  }
  if (/\.xlsx$/i.test(name)) {
    const strings = parts(/^xl\/sharedStrings\.xml$/).map((p) => xmlText(read(p), "t", "si"));
    // Numbers and inline strings live in the sheets: a card number in a cell is a number there.
    const sheets = parts(/^xl\/worksheets\/sheet\d+\.xml$/).map((p) => {
      const doc = new DOMParser().parseFromString(read(p), "application/xml");
      return [...doc.getElementsByTagName("row")].map((row) =>
        [...row.getElementsByTagName("c")].filter((c) => c.getAttribute("t") !== "s").map((c) => c.textContent).filter(Boolean).join("\t")).filter(Boolean).join("\n");
    });
    return [...strings, ...sheets].join("\n");
  }
  if (/\.(odt|ods|odp)$/i.test(name)) {
    const doc = new DOMParser().parseFromString(read("content.xml"), "application/xml");
    const lines = [...doc.getElementsByTagName("*")].filter((e) => e.localName === "p" || e.localName === "h").map((e) => e.textContent);
    return lines.join("\n");
  }
  return null;
}

export async function extract(name, base64) {
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  if (/\.pdf$/i.test(name)) return pdfText(bytes);
  return officeText(name, bytes);
}

// The text inside a file, so it can be checked before it is uploaded. Plain text and code are read here;
// PDF and Office documents are read by the extension's offscreen page (see src/offscreen/extract.js),
// which keeps pdf.js out of every AI tab. Anything else (images, archives) cannot be checked: null.

const TEXT_TYPES = /^text\/|json|xml|yaml|toml|javascript|ecmascript|x-sh|x-python|csv|x-httpd-php|sql|graphql|x-pem-file|x-x509/;
const TEXT_NAMES = /\.(txt|md|markdown|rst|csv|tsv|json|jsonl|ndjson|geojson|xml|ya?ml|toml|ini|cfg|conf|config|env|properties|pem|key|crt|cer|csr|pub|p8|log|sql|sh|bash|zsh|fish|ps1|psm1|bat|cmd|py|ipynb|js|mjs|cjs|ts|tsx|jsx|java|kt|kts|go|rb|php|cs|vb|fs|c|cc|cpp|cxx|h|hh|hpp|rs|swift|scala|r|m|mm|pl|pm|lua|dart|vue|svelte|astro|html?|css|scss|sass|less|graphql|gql|proto|tf|tfvars|hcl|gradle|sbt|nix|dockerfile|gitignore|gitconfig|npmrc|yarnrc|pypirc|netrc|htpasswd|pgpass|rtf|srt|vtt|tex|bib|diff|patch|eml|ics|vcf)$/i;
const TEXT_BASENAMES = /^(\.env(\..*)?|dockerfile|makefile|procfile|gemfile|rakefile|vagrantfile|jenkinsfile|id_rsa|id_dsa|id_ecdsa|id_ed25519|credentials|config|known_hosts|authorized_keys|\.?[a-z]+rc)$/i;
export const DOCUMENTS = /\.(pdf|docx|xlsx|pptx|odt|ods|odp)$/i;
export const IMAGES = /\.(png|jpe?g|webp|bmp|gif)$/i;
/** Files whose text is read in the offscreen page; a redacted copy of one is plain text. */
export const needsReader = (file) => DOCUMENTS.test(file.name ?? "") || IMAGES.test(file.name ?? "") || /^application\/pdf$|officedocument|opendocument|^image\/(png|jpeg|webp|bmp|gif)$/.test(file.type);

function looksLikeText(bytes) {
  if (bytes.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, Math.max(0, bytes.length - 4)));
    return true;
  } catch {
    return false;
  }
}

/** The file's text, or null when it is not something that can be read as text. */
export async function extractText(file, readDocument) {
  const name = file.name ?? "";
  // Documents and images first: Office types contain "xml" ("...wordprocessingml.document"), but they are zip files.
  if (needsReader(file)) {
    return readDocument ? readDocument(file) : null;
  }
  if (TEXT_TYPES.test(file.type) || TEXT_NAMES.test(name) || TEXT_BASENAMES.test(name)) {
    return new TextDecoder("utf-8").decode(await file.arrayBuffer());
  }
  if (file.type && !file.type.startsWith("application/octet-stream")) return null; // images, video, archives
  const head = new Uint8Array(await file.slice(0, 8192).arrayBuffer());
  return looksLikeText(head) ? new TextDecoder("utf-8").decode(await file.arrayBuffer()) : null;
}

/** Bytes as base64, in chunks (runtime messages carry JSON, not ArrayBuffers). */
export async function toBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

// What every rule means to a person: a title, how serious it is, what placeholder replaces it, and the
// explanation the guard shows (why it matters, what to do). Severities match the engine's catalog
// (src/shadowlens/analysis/catalog.py); tests/unit/rules.test.mjs checks that every rule is covered.

const KEY_WHY = "Anyone who can read this conversation, including the AI provider's staff, logs and future model training, could use it to act as you.";
const KEY_FIX = [
  "Send the redacted version: the AI still sees where the key goes, not the key.",
  "If it was already sent somewhere, rotate it in the provider's console.",
  "Keep keys in environment variables or a secrets manager, and paste code that reads them.",
];

const PII_WHY = "This is someone's personal data. Sharing it with an AI provider may break privacy law (GDPR, India's DPDP Act) or your company's rules.";
const PII_FIX = [
  "Send the redacted version: the AI can still help with the format or the logic.",
  "Use made-up sample data when you need realistic examples.",
];

function secret(title, placeholder, severity, why = KEY_WHY, fix = KEY_FIX) {
  return { title, placeholder, severity, kind: "secret", redactable: true, why, fix };
}

function pii(title, placeholder, severity, why = PII_WHY, fix = PII_FIX) {
  return { title, placeholder, severity, kind: "personal", redactable: true, why, fix };
}

export const RULES = {
  SEC_PRIVATE_KEY: secret("Private key", "PRIVATE_KEY", "critical",
    "A private key proves identity for a server, a person or a service. Once shared it cannot be made safe again.",
    ["Do not send it: describe the problem instead, or paste the public key.",
      "If it was already shared, generate a new key pair and remove the old public key everywhere."]),
  SEC_AWS_SECRET_KEY: secret("AWS secret access key", "AWS_SECRET_ACCESS_KEY", "critical"),
  SEC_GITHUB_TOKEN: secret("GitHub token", "GITHUB_TOKEN", "critical"),
  SEC_STRIPE_KEY: secret("Stripe live key", "STRIPE_KEY", "critical",
    "A live Stripe key can move real money and read customer payment data."),
  SEC_DB_URL: secret("Database connection string with a password", "DATABASE_URL", "critical",
    "The connection string includes a password that opens your database.",
    ["Send the redacted version.", "Share the schema or the query, never the credentials.",
      "Use a read-only account for anything you debug with an AI."]),
  SEC_AWS_ACCESS_KEY: secret("AWS access key ID", "AWS_ACCESS_KEY_ID", "high"),
  SEC_OPENAI_KEY: secret("OpenAI API key", "OPENAI_API_KEY", "high"),
  SEC_ANTHROPIC_KEY: secret("Anthropic API key", "ANTHROPIC_API_KEY", "high"),
  SEC_SLACK_TOKEN: secret("Slack token or webhook", "SLACK_TOKEN", "high"),
  SEC_GOOGLE_API_KEY: secret("Google API key", "GOOGLE_API_KEY", "high"),
  SEC_HF_TOKEN: secret("Hugging Face token", "HF_TOKEN", "high"),
  SEC_JWT: secret("Login token (JWT)", "JWT", "high",
    "A JSON Web Token is a live login: whoever holds it is signed in as that user until it expires."),
  SEC_GENERIC_ASSIGNMENT: secret("Possible password or secret", "SECRET", "medium",
    "This looks like a password, token or key written next to its name.",
    ["Send the redacted version.", "If it is not a secret, choose “Not a secret” and Shadow Lens will remember."]),
  SEC_HIGH_ENTROPY: secret("Random-looking string (possible secret)", "TOKEN", "low",
    "Long random strings are often keys or tokens. This one did not match a known format, so it may be harmless.",
    ["Send the redacted version if you are not sure.", "If it is a hash or an ID, choose “Not a secret”."]),
  PII_CREDIT_CARD: pii("Payment card number", "CARD_NUMBER", "high",
    "A card number passed the Luhn check, so it is very likely real. Sharing it breaks payment card rules (PCI DSS)."),
  PII_AADHAAR: pii("Aadhaar number", "AADHAAR", "high"),
  PII_IBAN: pii("Bank account number (IBAN)", "IBAN", "high"),
  PII_SSN: pii("US Social Security number", "SSN", "high"),
  PII_BULK: pii("A lot of personal data", "PERSONAL_DATA", "high"),
  PII_PAN: pii("PAN (Indian tax ID)", "PAN", "medium"),
  PII_EMAIL: pii("Email address", "EMAIL", "low"),
  PII_PHONE: pii("Phone number", "PHONE", "low"),
  PII_INTERNAL_HOST: pii("Internal host name or private IP", "INTERNAL_HOST", "low",
    "Internal names and addresses map out your company network for anyone who reads them.",
    ["Send the redacted version.", "Use example names such as db.example.com."]),
  CODE_CONFIDENTIAL_MARKER: {
    title: "Code marked confidential", placeholder: null, severity: "medium", kind: "code", redactable: false,
    why: "The text carries a confidentiality notice next to a copyright line: it is probably not yours to share.",
    fix: ["Check your company's policy for AI tools before sending it.", "Share a small, generic snippet instead."],
  },
  CODE_POSSIBLE_SOURCE: {
    title: "Looks like source code", placeholder: null, severity: "low", kind: "code", redactable: false,
    why: "Large blocks of internal code can reveal how your systems work.",
    fix: ["Make sure this code is allowed to leave your company.", "Strip names, hosts and keys first."],
  },
  HIDDEN_TEXT: {
    title: "Hidden characters or instructions", placeholder: null, severity: "high", kind: "injection", redactable: false,
    why: "Text copied from a web page or document carries invisible characters or instructions aimed at the AI. This is how prompt-injection attacks hide.",
    fix: ["Paste the cleaned version, which removes the invisible characters.", "Read the text before sending it to an AI with tools or file access."],
  },
  INJECTION_PHRASE: {
    title: "Instructions aimed at the AI", placeholder: null, severity: "medium", kind: "injection", redactable: false,
    why: "The text tells the AI to ignore its instructions, reveal them, or send data somewhere. If it came from a web page or a file, someone may be trying to take over your assistant.",
    fix: ["Only send it if you wrote it, or if you are asking the AI about it on purpose.", "Never send such text to an AI that can use tools, browse or read your files."],
  },
};

export const SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"];

export function severityRank(severity) {
  return Math.max(0, SEVERITY_ORDER.indexOf(severity));
}

export function ruleInfo(ruleId) {
  return RULES[ruleId] ?? {
    title: ruleId, placeholder: "SECRET", severity: "medium", kind: "secret", redactable: true,
    why: "Shadow Lens flagged this as sensitive.", fix: ["Send the redacted version."],
  };
}

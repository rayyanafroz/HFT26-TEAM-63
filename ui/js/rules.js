// Display names for the frozen rule catalog (SOT 6.5) and OWASP LLM Top 10 (2025) ids.
export const RULES = {
  SEC_PRIVATE_KEY: "Private key", SEC_AWS_SECRET_KEY: "AWS secret key", SEC_GITHUB_TOKEN: "GitHub token",
  SEC_STRIPE_KEY: "Stripe key", SEC_DB_URL: "Database URL with password", SEC_AWS_ACCESS_KEY: "AWS access key id",
  SEC_OPENAI_KEY: "OpenAI key", SEC_ANTHROPIC_KEY: "Anthropic key", SEC_SLACK_TOKEN: "Slack token",
  SEC_GOOGLE_API_KEY: "Google API key", SEC_HF_TOKEN: "Hugging Face token", SEC_JWT: "JSON web token",
  SEC_GENERIC_ASSIGNMENT: "Secret assignment", SEC_HIGH_ENTROPY: "High-entropy string",
  PII_CREDIT_CARD: "Card number", PII_AADHAAR: "Aadhaar number", PII_IBAN: "IBAN", PII_SSN: "US SSN",
  PII_BULK: "Bulk personal data", PII_PAN: "PAN", PII_EMAIL: "Email address", PII_PHONE: "Phone number",
  PII_INTERNAL_HOST: "Internal hostname",
  CODE_CONFIDENTIAL_MARKER: "Confidential marker", CODE_POSSIBLE_SOURCE: "Possible source code",
  AGENT_DANGEROUS_CMD: "Dangerous command", AGENT_SENSITIVE_FILE_READ: "Sensitive file read",
  AGENT_SHELL_EXEC: "Shell command run", AGENT_EGRESS_COMMAND: "Data sent out by command",
  AGENT_MCP_TOOL_CALL: "MCP tool call", AGENT_FS_READ_OUTSIDE_WORKSPACE: "File read outside workspace",
  AGENT_SHELL_TOOL_DECLARED: "Shell tool declared", AGENT_EXCESSIVE_AGENCY: "Excessive agency",
  AGENT_INJECTION_CHAIN: "Injection chain", AGENT_NETWORK_TOOL: "Network tool",
  POLICY_UNSANCTIONED_TOOL: "Unapproved tool", POLICY_LOCAL_LLM: "Local model",
};
export const ruleName = (id) => RULES[id] ?? id ?? "–";

export const OWASP = {
  LLM01: "Prompt Injection", LLM02: "Sensitive Information Disclosure", LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning", LLM05: "Improper Output Handling", LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage", LLM08: "Vector and Embedding Weaknesses", LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};
export const owaspName = (id) => (OWASP[id] ? `${id} ${OWASP[id]}` : id);

/** Where a finding came from. Events carry source (SOT 6.2); alerts do not yet, so this reads an optional field. */
const SOURCES = { live_log: "live log", http_log: "upload", har: "upload", pcap: "upload", conn_scan: "scan", scenario: "scenario",
  transcript: "live transcript", ollama_tap: "Ollama tap" };
export const sourceName = (s) => (s ? SOURCES[s] ?? s : "–");

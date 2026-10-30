"""Human-readable titles for every rule id (used as the title of alerts and Leak Lab findings).

One table, shared by the pipeline (alerts) and the analyzer's preview (Leak Lab), so the
same rule always reads the same everywhere.
"""

from __future__ import annotations

RULE_TITLES: dict[str, str] = {
    # secrets
    "SEC_PRIVATE_KEY": "Private key sent to an AI tool",
    "SEC_AWS_SECRET_KEY": "AWS secret access key sent to an AI tool",
    "SEC_GITHUB_TOKEN": "GitHub token sent to an AI tool",
    "SEC_STRIPE_KEY": "Stripe API key sent to an AI tool",
    "SEC_DB_URL": "Database connection string sent to an AI tool",
    "SEC_AWS_ACCESS_KEY": "AWS access key ID sent to an AI tool",
    "SEC_OPENAI_KEY": "OpenAI-style API key sent to an AI tool",
    "SEC_ANTHROPIC_KEY": "Anthropic-style API key sent to an AI tool",
    "SEC_SLACK_TOKEN": "Slack token sent to an AI tool",
    "SEC_GOOGLE_API_KEY": "Google API key sent to an AI tool",
    "SEC_HF_TOKEN": "Hugging Face token sent to an AI tool",
    "SEC_JWT": "JSON Web Token sent to an AI tool",
    "SEC_GENERIC_ASSIGNMENT": "Possible secret assignment sent to an AI tool",
    "SEC_HIGH_ENTROPY": "High-entropy string (possible secret) sent to an AI tool",
    # personal data
    "PII_CREDIT_CARD": "Payment card number sent to an AI tool",
    "PII_AADHAAR": "Aadhaar number sent to an AI tool",
    "PII_IBAN": "Bank account number (IBAN) sent to an AI tool",
    "PII_SSN": "Social Security number sent to an AI tool",
    "PII_BULK": "Bulk personal data sent to an AI tool",
    "PII_PAN": "PAN (tax ID) sent to an AI tool",
    "PII_EMAIL": "Email address sent to an AI tool",
    "PII_PHONE": "Phone number sent to an AI tool",
    "PII_INTERNAL_HOST": "Internal host name sent to an AI tool",
    # code
    "CODE_CONFIDENTIAL_MARKER": "Confidential-marked code sent to an AI tool",
    "CODE_POSSIBLE_SOURCE": "Possible internal source code sent to an AI tool",
    # agents
    "AGENT_DANGEROUS_CMD": "Agent ran a dangerous command",
    "AGENT_SENSITIVE_FILE_READ": "Agent read a sensitive file",
    "AGENT_SHELL_EXEC": "Agent executed a shell command",
    "AGENT_EGRESS_COMMAND": "Agent ran a command that sends data out",
    "AGENT_MCP_TOOL_CALL": "Agent called an MCP tool",
    "AGENT_FS_READ_OUTSIDE_WORKSPACE": "Agent read files outside the workspace",
    "AGENT_SHELL_TOOL_DECLARED": "Agent has a shell tool available",
    "AGENT_EXCESSIVE_AGENCY": "Agent has broad permissions",
    "AGENT_INJECTION_CHAIN": "Possible prompt injection followed by a risky action",
    "AGENT_NETWORK_TOOL": "Agent has a network tool",
    # policy
    "POLICY_UNSANCTIONED_TOOL": "Unapproved AI tool in use",
    "POLICY_LOCAL_LLM": "Local AI model in use",
}


def title_for(rule_id: str) -> str:
    """The title for a rule id (the id itself if it is somehow unknown)."""
    return RULE_TITLES.get(rule_id, rule_id)

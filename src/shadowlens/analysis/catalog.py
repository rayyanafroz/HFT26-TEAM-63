"""The rule catalog (SOT 6.5) and the small types every detector shares.

Rule ids, severities and confidences are frozen; change them only through SOT 0.3.
Titles live in ``core/rule_titles.py``, shared with the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shadowlens.core.rule_titles import title_for
from shadowlens.models import category_for_rule

# Overlap priority, lower wins (SOT 7.3).
_NAMED_SECRET, _DB_URL, _CHECKSUM_PII, _GENERIC, _OTHER_PII, _ENTROPY = range(6)
_NOT_ON_SPANS = 9  # code and agent rules never compete for a span


@dataclass(frozen=True)
class Rule:
    severity: str
    confidence: float
    owasp: tuple[str, ...]
    priority: int = _NOT_ON_SPANS


_LLM02 = ("LLM02",)
_LLM06 = ("LLM06",)

RULES: dict[str, Rule] = {
    "SEC_PRIVATE_KEY": Rule("critical", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_AWS_SECRET_KEY": Rule("critical", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_GITHUB_TOKEN": Rule("critical", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_STRIPE_KEY": Rule("critical", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_DB_URL": Rule("critical", 0.9, _LLM02, _DB_URL),
    "SEC_AWS_ACCESS_KEY": Rule("high", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_OPENAI_KEY": Rule("high", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_ANTHROPIC_KEY": Rule("high", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_SLACK_TOKEN": Rule("high", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_GOOGLE_API_KEY": Rule("high", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_HF_TOKEN": Rule("high", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_JWT": Rule("high", 0.9, _LLM02, _NAMED_SECRET),
    "SEC_GENERIC_ASSIGNMENT": Rule("medium", 0.7, _LLM02, _GENERIC),
    "SEC_HIGH_ENTROPY": Rule("low", 0.5, _LLM02, _ENTROPY),
    "PII_CREDIT_CARD": Rule("high", 0.95, _LLM02, _CHECKSUM_PII),
    "PII_AADHAAR": Rule("high", 0.95, _LLM02, _CHECKSUM_PII),
    "PII_IBAN": Rule("high", 0.95, _LLM02, _CHECKSUM_PII),
    "PII_SSN": Rule("high", 0.8, _LLM02, _OTHER_PII),
    "PII_BULK": Rule("high", 0.9, _LLM02, _OTHER_PII),
    "PII_PAN": Rule("medium", 0.85, _LLM02, _OTHER_PII),
    "PII_EMAIL": Rule("low", 0.9, _LLM02, _OTHER_PII),
    "PII_PHONE": Rule("low", 0.6, _LLM02, _OTHER_PII),
    "PII_INTERNAL_HOST": Rule("low", 0.6, _LLM02, _OTHER_PII),
    "CODE_CONFIDENTIAL_MARKER": Rule("medium", 0.6, _LLM02),
    "CODE_POSSIBLE_SOURCE": Rule("low", 0.6, _LLM02),
    "AGENT_DANGEROUS_CMD": Rule("critical", 0.9, _LLM06),
    "AGENT_SENSITIVE_FILE_READ": Rule("high", 0.9, _LLM06),
    "AGENT_SHELL_EXEC": Rule("high", 0.9, _LLM06),
    "AGENT_EGRESS_COMMAND": Rule("high", 0.9, _LLM06),
    "AGENT_MCP_TOOL_CALL": Rule("medium", 0.9, _LLM06),
    "AGENT_FS_READ_OUTSIDE_WORKSPACE": Rule("medium", 0.7, _LLM06),
    "AGENT_SHELL_TOOL_DECLARED": Rule("medium", 0.9, _LLM06),
    "AGENT_EXCESSIVE_AGENCY": Rule("medium", 0.9, _LLM06),
    "AGENT_INJECTION_CHAIN": Rule("medium", 0.7, ("LLM01",)),
    "AGENT_NETWORK_TOOL": Rule("low", 0.9, _LLM06),
}


@dataclass(frozen=True)
class Candidate:
    """One raw detector match, before overlaps are resolved."""

    rule_id: str
    start: int
    end: int
    value: str


@dataclass
class TextFinding:
    """A finding from plain text. It holds no raw value, only masks and hashes."""

    rule_id: str
    masked_preview: str
    hash12: str
    spans: list[tuple[int, int]]
    context: str = ""
    count: int | None = None
    truncated: bool = field(default=False)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def category(self) -> str:
        return category_for_rule(self.rule_id).value

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def confidence(self) -> float:
        return self.rule.confidence

    @property
    def title(self) -> str:
        return title_for(self.rule_id)

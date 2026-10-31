"""Remediation written without a model (SOT 7.7). Used in template mode and whenever the model cannot be used.

Which template an alert gets depends on its rule; the first matching row wins and the last row catches
anything else. The advice is the same for every alert of a kind, so it never contains anything from the traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from ..models import (Alert, RedactionCheck, Remediation, RemediationSource, Sensitivity, Verdict,
                      new_id, utc_now_iso)


@dataclass(frozen=True)
class Template:
    key: str
    summary: str
    steps: tuple[str, ...]
    data_classes: tuple[str, ...]


TEMPLATES: dict[str, Template] = {t.key: t for t in (
    Template("cloud_key",
             "A cloud service key was sent to an AI tool. Anyone who can read that tool's logs or history could use it.",
             ("Revoke or rotate the key in the provider's console now.",
              "Check the provider's usage logs for activity you do not recognize.",
              "Remove the key from the prompt, file or history where it was pasted.",
              "Keep keys in a secrets manager or environment variable, not in prompts or source files."),
             ("credential",)),
    Template("db_credential",
             "A database or generic credential was sent to an AI tool. It may give access to stored data.",
             ("Change the password or token that was exposed.",
              "Review recent logins to that system for anything unusual.",
              "Use a read-only account or a short-lived token when sharing context with AI tools.",
              "Move the value into a secrets manager."),
             ("credential",)),
    Template("private_key",
             "A private key was sent to an AI tool. It identifies a person or system and cannot be made safe again.",
             ("Treat the key as compromised and generate a new key pair.",
              "Remove the old public key from servers, repositories and services that trust it.",
              "Check access logs for use of the old key.",
              "Never paste key files into AI tools."),
             ("credential", "private_key")),
    Template("pii",
             "Personal data was sent to an AI tool. Depending on the data it may need to be reported or deleted.",
             ("Find out whose data it is and whether a lawful basis allows sharing it with this provider.",
              "Ask the provider to delete the conversation if that is possible.",
              "Record the incident for your privacy or compliance contact.",
              "Mask or replace personal data before using AI tools."),
             ("pii",)),
    Template("code",
             "Internal or confidential source code was sent to an AI tool.",
             ("Check whether your policy allows sharing this code with the provider.",
              "Ask the provider to delete the conversation and confirm its training settings.",
              "Look for secrets or customer data inside the shared code.",
              "Share minimal snippets, or use an approved tool for internal code."),
             ("source_code",)),
    Template("local_llm",
             "A local model server is running. Data stays on this machine, but the tool is not on the approved list.",
             ("Confirm who runs it and why.",
              "Approve it for your organisation if it is acceptable, which lowers its risk score.",
              "Make sure the server is bound to this machine only."),
             ("usage",)),
    Template("unsanctioned_tool",
             "An AI tool that is not on the approved list is in use.",
             ("Find out who uses it and for what.",
              "Approve the provider if it is acceptable, or ask users to switch to an approved tool.",
              "Share the acceptable-use policy for AI tools with the team."),
             ("usage",)),
    Template("agent_shell",
             "An AI agent ran or attempted a shell command that is risky.",
             ("Check what the command did and whether it was expected.",
              "Look at the files, network connections and processes it touched.",
              "Limit the agent's shell access, or require approval for commands.",
              "Rotate any secret the command could have read."),
             ("agent_action",)),
    Template("agent_file",
             "An AI agent read, or tried to read, a file it does not normally need.",
             ("Check which file was read and whether it holds secrets or personal data.",
              "Rotate any credential that was in the file.",
              "Restrict the agent's file access to the project folder."),
             ("agent_action",)),
    Template("generic",
             "ShadowLens flagged something that needs a person to look at it.",
             ("Open the finding and read what was detected.",
              "Decide whether it is real and whether it needs action.",
              "Acknowledge the alert when you have dealt with it."),
             ()),
)}

# First match wins. Patterns are fnmatch globs on the rule id.
_RULE_TEMPLATES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("SEC_PRIVATE_KEY",), "private_key"),
    (("SEC_DB_URL", "SEC_GENERIC_ASSIGNMENT", "SEC_JWT"), "db_credential"),
    (("SEC_*",), "cloud_key"),
    (("PII_*",), "pii"),
    (("CODE_*",), "code"),
    (("POLICY_LOCAL_LLM",), "local_llm"),
    (("POLICY_UNSANCTIONED_TOOL",), "unsanctioned_tool"),
    (("AGENT_SENSITIVE_FILE_READ", "AGENT_FS_READ_OUTSIDE_WORKSPACE", "AGENT_MCP*", "AGENT_NETWORK*"), "agent_file"),
    (("AGENT_*",), "agent_shell"),
)


def template_key(rule_id: str) -> str:
    for patterns, key in _RULE_TEMPLATES:
        if any(fnmatchcase(rule_id, p) for p in patterns):
            return key
    return "generic"


def template_for(rule_id: str) -> Template:
    return TEMPLATES[template_key(rule_id)]


def from_template(alert: Alert, *, redaction_check: RedactionCheck = RedactionCheck.NOT_APPLICABLE) -> Remediation:
    """Advice for an alert with no model involved. ``sensitivity`` follows the alert's severity."""
    t = template_for(alert.rule_id)
    sensitivity = Sensitivity(alert.severity.value) if alert.severity.value != "info" else Sensitivity.LOW
    return Remediation(
        id=new_id(), alert_id=alert.id, summary=t.summary, steps=list(t.steps), sensitivity=sensitivity,
        verdict=Verdict.NEEDS_REVIEW, data_classes=list(t.data_classes), source=RemediationSource.TEMPLATE,
        redaction_check=redaction_check, created_at=utc_now_iso())

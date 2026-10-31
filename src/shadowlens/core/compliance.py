"""Which compliance controls have a gap (SOT 7.6).

The mapping from rules to controls is data (``config/compliance.yaml``). A control has a gap when a mapped
finding is still open, meaning its alert has not been acknowledged (a finding that never raised an alert is
always open). This is an interpretation of risk, not an audit, and the response says so.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml
from pydantic import Field, ValidationError

from ..models import Compliance, Control, ControlStatus, RiskBlock, ShadowModel

PROJECT_DIR = Path(__file__).resolve().parents[3]
DEFAULT_PATH = PROJECT_DIR / "config" / "compliance.yaml"


class ComplianceConfigError(ValueError):
    """The compliance mapping file is missing or invalid."""


class ControlDef(ShadowModel):
    id: str = Field(min_length=1)
    framework: str = Field(min_length=1)
    title: str = Field(min_length=1)
    rules: list[str] = Field(min_length=1)


def load_controls(path: Path | str | None = None) -> list[ControlDef]:
    file = Path(path) if path is not None else DEFAULT_PATH
    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ComplianceConfigError(f"compliance mapping not found: {file}") from exc
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ComplianceConfigError(f"cannot read compliance mapping {file}: {type(exc).__name__}") from exc
    if not isinstance(raw, dict) or set(raw) != {"controls"} or not isinstance(raw["controls"], list):
        raise ComplianceConfigError(f"{file}: expected a mapping with only a 'controls' list")
    controls: list[ControlDef] = []
    for index, entry in enumerate(raw["controls"]):
        try:
            controls.append(ControlDef.model_validate(entry))
        except ValidationError as exc:
            label = entry.get("id", f"#{index}") if isinstance(entry, dict) else f"#{index}"
            raise ComplianceConfigError(f"{file}: control {label}: {exc.errors()[0]['msg']}") from exc
    ids = [c.id for c in controls]
    if len(set(ids)) != len(ids):
        raise ComplianceConfigError(f"{file}: duplicate control ids")
    return controls


def rule_matches(rule_id: str, pattern: str) -> bool:
    return rule_id.startswith(pattern[:-1]) if pattern.endswith("*") else rule_id == pattern


@dataclass(frozen=True)
class OpenFinding:
    id: str
    rule_id: str


def evaluate(definitions: Iterable[ControlDef], findings: Iterable[OpenFinding]) -> list[Control]:
    rows = list(findings)
    controls = []
    for d in definitions:
        ids = [f.id for f in rows if any(rule_matches(f.rule_id, p) for p in d.rules)]
        controls.append(Control(id=d.id, framework=d.framework, title=d.title,
                                status=ControlStatus.GAP if ids else ControlStatus.OK,
                                finding_count=len(ids), finding_ids=ids))
    return controls


def build(definitions: Iterable[ControlDef], findings: Iterable[OpenFinding], risk: RiskBlock) -> Compliance:
    return Compliance(compliance_score=risk.compliance_score, org_risk=risk.org_risk, band=risk.band,
                      controls=evaluate(definitions, findings))

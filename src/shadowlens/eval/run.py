"""Measures detection on labeled fixtures and writes ``data/evidence.json`` (SOT 8.5).

Run from the project folder: ``python -m shadowlens.eval.run``. The Evidence screen only
shows what this measured; no metric value is written by hand anywhere.

Mistakes are reported by row id and rule id, never by value.
"""

from __future__ import annotations

import json
import re
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shadowlens.analysis import AnalysisSettings, analyze, redact_path
from shadowlens.config import Config
from shadowlens.core.ctx import AgentSessionContext
from shadowlens.fakes import expand, fake
from shadowlens.models import Evidence, EvidenceMetric, NetEvent, utc_now_iso

COMMAND = "python -m shadowlens.eval.run"
PAYLOADS = "fixtures/payloads_labeled.jsonl"
AGENTS = "fixtures/agent_labeled.jsonl"

_FAKE_TOKEN_RE = re.compile(r"\{\{fake:([a-z0-9_]+)(?:#(\d+))?\}\}")
_TOOL_ID = "eval|openai"
_SPEED_MIN_EVENTS = 2000
_SPEED_PADDING = "Please review this function and tell me why the build is failing on Windows. " * 20


@dataclass
class Row:
    id: str
    input: dict[str, Any]
    expect: list[str]
    raw: str


@dataclass
class RowResult:
    row: Row
    fired: list[str]
    critical: list[str]
    dumped: str


@dataclass
class Report:
    metrics: list[EvidenceMetric] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def load_rows(path: Path) -> list[Row]:
    rows = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        if raw.strip():
            data = json.loads(expand(raw))
            rows.append(Row(data["id"], data["input"], data["expect"], raw))
    return rows


def _event(fields: dict[str, Any]) -> NetEvent:
    body = fields.get("body")
    return NetEvent(
        id=str(uuid.uuid4()), ts=utc_now_iso(), source="http_log", process="eval", dst_ip="0.0.0.0", dst_port=443,
        host="api.openai.com", host_basis="host_header", method="POST", path=fields.get("path", "/v1/chat/completions"),
        query=fields.get("query"), headers=fields.get("headers") or {},
        body_text=body if isinstance(body, str) or body is None else json.dumps(body),
    )


def run_row(row: Row, settings: AnalysisSettings) -> RowResult:
    """Each row gets a fresh context, so rows cannot affect each other."""
    event = _event(row.input)
    result = analyze(event, settings, AgentSessionContext(tool_id=_TOOL_ID),
                     native_key_rules=row.input.get("native_key_rules", ()))
    dumped = json.dumps([item.model_dump(mode="json") for item in result.findings + result.agent_activity])
    return RowResult(
        row,
        [finding.rule_id for finding in result.findings],
        [finding.rule_id for finding in result.findings if finding.severity.value == "critical"],
        dumped + (redact_path(event.path, settings) if event.path else ""),
    )


def _metric(id_: str, label: str, value: float, target: float, unit: str, passed: bool, fixture: str) -> EvidenceMetric:
    return EvidenceMetric(id=id_, label=label, value=round(value, 2), target=target, unit=unit, passed=passed,
                          fixture=fixture, command=COMMAND)


def _recall(results: list[RowResult], prefix: str, report: Report) -> float:
    labeled = hit = 0
    for result in results:
        for rule_id in result.row.expect:
            if rule_id.startswith(prefix):
                labeled += 1
                if rule_id in result.fired:
                    hit += 1
                else:
                    report.problems.append(f"missed {rule_id} in row {result.row.id}")
    return 100.0 * hit / labeled if labeled else 0.0


def _false_positives(results: list[RowResult], report: Report) -> int:
    count = 0
    for result in results:
        for rule_id in result.fired:
            if rule_id not in result.row.expect:
                count += 1
                report.problems.append(f"false positive {rule_id} in row {result.row.id}")
    return count


def _raw_leaks(results: list[RowResult], report: Report) -> int:
    """AT-12: a fake that went in must not come back out, whole or from its middle."""
    leaks = 0
    for result in results:
        for kind, idx in _FAKE_TOKEN_RE.findall(result.row.raw):
            value = fake(kind, int(idx or 0))
            if value in result.dumped or (len(value) >= 12 and value[4:12] in result.dumped):
                leaks += 1
                report.problems.append(f"raw {kind} visible in the output of row {result.row.id}")
    return leaks


def _speed(rows: list[Row], settings: AnalysisSettings) -> tuple[float, float]:
    """Timed on prompts of a realistic size. The fixture rows alone are far too short to be honest."""
    events = []
    for row in rows:
        text = row.input.get("body")
        text = text if isinstance(text, str) else json.dumps(text)
        events.append(_event({"body": {"model": "m", "messages": [{"role": "user", "content": _SPEED_PADDING + text}]}}))
    latencies: list[float] = []
    started = time.perf_counter()
    while len(latencies) < _SPEED_MIN_EVENTS:
        ctx = AgentSessionContext(tool_id=_TOOL_ID)
        for event in events:
            before = time.perf_counter()
            analyze(event, settings, ctx)
            latencies.append(time.perf_counter() - before)
    elapsed = time.perf_counter() - started
    return len(latencies) / elapsed, statistics.quantiles(latencies, n=20)[18] * 1000


def evaluate(base_dir: Path, settings: AnalysisSettings) -> Report:
    report = Report()
    payload_path = base_dir / PAYLOADS
    agent_path = base_dir / AGENTS
    payload_rows = load_rows(payload_path) if payload_path.exists() else []
    agent_rows = load_rows(agent_path) if agent_path.exists() else []
    payloads = [run_row(row, settings) for row in payload_rows]
    agents = [run_row(row, settings) for row in agent_rows]

    if payloads:
        secret = _recall(payloads, "SEC_", report)
        pii = _recall(payloads, "PII_", report)
        false_positives = _false_positives(payloads, report)
        report.metrics += [
            _metric("secret_recall", "Secret recall", secret, 95, "%", secret >= 95, PAYLOADS),
            _metric("pii_recall", "Personal data recall", pii, 95, "%", pii >= 95, PAYLOADS),
            _metric("false_positives", "False positives", false_positives, 2, "count", false_positives <= 2, PAYLOADS),
        ]
    if agents:
        labeled = sum(len(result.row.expect) for result in agents)
        hit = sum(rule_id in result.fired for result in agents for rule_id in result.row.expect)
        for result in agents:
            for rule_id in result.row.expect:
                if rule_id not in result.fired:
                    report.problems.append(f"missed {rule_id} in row {result.row.id}")
        rate = 100.0 * hit / labeled if labeled else 0.0
        # Unlabeled findings below critical are allowed here, per the AT-05 target.
        unlabeled_critical = 0
        for result in agents:
            for rule_id in result.critical:
                if rule_id not in result.row.expect:
                    unlabeled_critical += 1
                    report.problems.append(f"unlabeled critical {rule_id} in row {result.row.id}")
        report.metrics.append(_metric("agent_rules_hit", "Agent rules that fired", rate, 100, "%",
                                      rate == 100 and unlabeled_critical == 0, AGENTS))
    every = payloads + agents
    if every:
        leaks = _raw_leaks(every, report)
        report.metrics.append(_metric("no_raw_secret_leak", "Raw secrets in the output", leaks, 0, "count",
                                      leaks == 0, ", ".join(p for p, r in ((PAYLOADS, payloads), (AGENTS, agents)) if r)))
        per_second, p95 = _speed(payload_rows + agent_rows, settings)
        # Detection alone. The full pipeline target (AT-24) also has to fit the database.
        report.metrics += [
            _metric("events_per_s", "Detection speed, 1.6 KB prompts", per_second, 500, "events/s",
                    per_second >= 500, PAYLOADS),
            _metric("p95_latency_ms", "Detection time per event (p95)", p95, 500, "ms", p95 <= 500, PAYLOADS),
        ]
    return report


def write_evidence(report: Report, path: Path) -> Evidence:
    evidence = Evidence(available=bool(report.metrics), generated_at=utc_now_iso(), metrics=report.metrics)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence.model_dump(mode="json", by_alias=True), indent=2), encoding="utf-8")
    return evidence


def main(base_dir: Path | None = None) -> int:
    """Returns 0 when every metric meets its target."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    config = Config.load(base_dir=base_dir)
    report = evaluate(config.base_dir, AnalysisSettings.from_config(config))
    write_evidence(report, config.base_dir / "data" / "evidence.json")
    for metric in report.metrics:
        print(f"{'PASS' if metric.passed else 'FAIL'}  {metric.label}: {metric.value} {metric.unit} (target {metric.target})")
    for problem in report.problems:
        print(f"  {problem}")
    if not (config.base_dir / "fixtures" / "providers_labeled.jsonl").exists():
        print("note: provider_accuracy not measured yet (needs the classifier and providers_labeled.jsonl)")
    return 0 if report.metrics and all(metric.passed for metric in report.metrics) else 1


if __name__ == "__main__":
    raise SystemExit(main())

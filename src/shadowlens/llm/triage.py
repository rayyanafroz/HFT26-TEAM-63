"""Advice for an alert, from an AI model when allowed and from a template otherwise (SOT 7.7).

The model only gives a second opinion on a finding the rules already raised. It never changes the severity,
the score or whether an alert exists. The order for every call is: build the prompt (redacted pieces only),
run the egress guard on the whole outgoing text, send, validate the reply. Anything that goes wrong at any
step ends in a template remediation, and every attempt is written to the egress ledger.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

import httpx

from ..config import Config
from ..db import Database
from ..models import (Alert, LlmCall, LlmStatus, RedactionCheck, Remediation, RemediationSource, Sensitivity,
                      Severity, Verdict, new_id, utc_now_iso)
from ..providers.catalog import Catalog
from . import guard
from .templates import from_template

log = logging.getLogger("shadowlens.triage")

AUTO_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})
WORKERS = 2
MAX_TOKENS = 400
TEMPERATURE = 0.2
SUMMARY_MAX, STEP_MAX, STEPS_MAX = 300, 200, 5
CLASS_MAX_CHARS, CLASS_MAX_ITEMS = 40, 8

Publish = Callable[[str, Any], None]
_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


class BadReply(ValueError):
    """The model's answer was not the JSON we asked for."""


def parse_reply(content: str) -> dict[str, Any]:
    """The model's text as a validated dict, with lengths clamped. Raises ``BadReply``."""
    try:
        data = json.loads(_FENCE.sub("", content.strip()))
    except (json.JSONDecodeError, RecursionError, AttributeError) as exc:
        raise BadReply("not JSON") from exc
    if not isinstance(data, dict):
        raise BadReply("not an object")
    try:
        summary, steps, classes = data["summary"], data["steps"], data["data_classes"]
        sensitivity, verdict = Sensitivity(data["sensitivity"]), Verdict(data["verdict"])
    except (KeyError, ValueError) as exc:
        raise BadReply("a key is missing or has an unknown value") from exc
    if not isinstance(summary, str) or not isinstance(steps, list) or not isinstance(classes, list):
        raise BadReply("wrong types")
    if not all(isinstance(x, str) for x in steps) or not all(isinstance(x, str) for x in classes):
        raise BadReply("wrong types in a list")
    return {"summary": summary.strip()[:SUMMARY_MAX],
            "steps": [x.strip()[:STEP_MAX] for x in steps if x.strip()][:STEPS_MAX],
            "sensitivity": sensitivity, "verdict": verdict,
            "data_classes": [x.strip()[:CLASS_MAX_CHARS] for x in classes if x.strip()][:CLASS_MAX_ITEMS]}


class Triage:
    def __init__(self, config: Config, db: Database, catalog: Catalog, *, publish: Publish | None = None,
                 sanctioned: Callable[[str], bool] | None = None,
                 check: Callable[[str, Any], bool] | None = None,
                 transport: httpx.BaseTransport | None = None, workers: int = WORKERS):
        self._config, self._db, self._catalog = config, db, catalog
        self._publish = publish
        self._sanctioned = sanctioned or (lambda provider_id: provider_id in config.sanctioned)
        self._check = check
        self._transport = transport
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="shadowlens-triage")
        self._lock = threading.Lock()
        self._busy: dict[str, threading.Lock] = {}

    # ---- when it runs -------------------------------------------------------

    def on_alert(self, alert: Alert) -> None:
        """A new alert was raised. High and critical ones get advice in the background."""
        if alert.severity not in AUTO_SEVERITIES or alert.remediation is not None:
            return
        try:
            self._pool.submit(self._auto, alert)
        except RuntimeError:                 # shutting down
            pass

    def _auto(self, alert: Alert) -> None:
        try:
            if self._db.get_remediation(alert.id) is not None:
                return
            if self._config.llm_mode == "llm" and self._used_calls() >= self._config.llm_max_auto:
                self.remediate(alert, use_model=False)           # the automatic budget is spent: templates only
            else:
                self.remediate(alert)
        except Exception:  # noqa: BLE001 - a background job must not die loudly; the alert is already stored
            log.warning("automatic triage failed", exc_info=True)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _used_calls(self) -> int:
        return self._db.list_llm_calls(limit=1).total

    # ---- one alert ------------------------------------------------------------

    def remediate(self, alert: Alert, *, use_model: bool = True) -> Remediation:
        """Advice for ``alert``. Idempotent: an alert that has some already returns it."""
        with self._lock:
            gate = self._busy.setdefault(alert.id, threading.Lock())
        try:
            with gate:
                existing = self._db.get_remediation(alert.id)
                if existing is not None:
                    return existing
                made = self._llm(alert) if use_model and self._config.llm_mode == "llm" else None
                stored = self._db.save_remediation(made or from_template(alert))
        finally:
            with self._lock:
                self._busy.pop(alert.id, None)
        if self._publish is not None:
            self._publish("remediation.update", stored)
        return stored

    def _provider(self, alert: Alert) -> tuple[str, bool]:
        provider = self._catalog.get(alert.provider_id)
        return (provider.display_name if provider else alert.provider_id), self._sanctioned(alert.provider_id)

    def _llm(self, alert: Alert) -> Remediation | None:
        """The model's advice, or ``None`` after writing why not to the ledger (the caller then uses a template)."""
        name, sanctioned = self._provider(alert)
        prompt = guard.user_prompt(alert, provider_name=name, sanctioned=sanctioned,
                                   send_context=self._config.llm_send_context)
        size, digest = len(guard.outgoing_text(prompt).encode("utf-8")), guard.sha256_of(prompt)

        def record(status: LlmStatus, latency: int | None, model: str | None) -> None:
            self._db.add_llm_call(LlmCall(id=new_id(), ts=utc_now_iso(), alert_id=alert.id, model=model,
                                          bytes=size, status=status, prompt_sha256=digest, latency_ms=latency))

        if not guard.is_allowed(prompt, self._config, self._check):
            record(LlmStatus.BLOCKED, None, None)
            return from_template(alert, redaction_check=RedactionCheck.BLOCKED)
        model = self._config.featherless_model
        started = time.monotonic()
        try:
            reply = parse_reply(self._request(prompt))
        except (httpx.HTTPError, BadReply, KeyError, IndexError, TypeError, ValueError) as exc:
            record(LlmStatus.FAILED, int((time.monotonic() - started) * 1000), model)
            log.info("model call failed (%s); using a template", type(exc).__name__)
            return from_template(alert, redaction_check=RedactionCheck.PASSED)
        latency = int((time.monotonic() - started) * 1000)
        record(LlmStatus.SENT, latency, model)
        return Remediation(id=new_id(), alert_id=alert.id, summary=reply["summary"], steps=reply["steps"],
                           sensitivity=reply["sensitivity"], verdict=reply["verdict"],
                           data_classes=reply["data_classes"], source=RemediationSource.LLM, model=model,
                           latency_ms=latency, redaction_check=RedactionCheck.PASSED, prompt_text=prompt,
                           created_at=utc_now_iso())

    def _request(self, prompt: str) -> str:
        c = self._config
        with httpx.Client(transport=self._transport, timeout=c.llm_timeout_s) as client:
            response = client.post(
                f"{c.featherless_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {c.featherless_api_key}"},
                json={"model": c.featherless_model, "temperature": TEMPERATURE, "max_tokens": MAX_TOKENS,
                      "messages": [{"role": "system", "content": guard.SYSTEM_PROMPT},
                                   {"role": "user", "content": prompt}]})
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]

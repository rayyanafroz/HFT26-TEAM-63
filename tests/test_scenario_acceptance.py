"""AT-08: each demo scenario, loaded through the real parser, analyzer, pipeline, scoring and API,
meets the numbers the SOT promises (SOT 8.2). If one misses, tune the scenario file, never the formula."""

import pytest
from fastapi.testclient import TestClient

from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.db import Database


@pytest.fixture
def run(tmp_path):
    def load(name):
        cfg = Config.load(env={"SHADOWLENS_RESOLVE": "false", "SHADOWLENS_LIVE_DIR": str(tmp_path / "live")},
                          base_dir=tmp_path, use_dotenv=False)
        db = Database(tmp_path / f"{name}.db")
        with TestClient(create_app(cfg, db=db, ui_dir=tmp_path / "none")) as c:
            summary_of_load = c.post("/api/demo/load-scenario", json={"name": name}).json()
            return {
                "events": summary_of_load["accepted"] + summary_of_load["dropped_non_ai"],
                "summary": c.get("/api/stats/summary").json(),
                "findings": c.get("/api/findings", params={"limit": 1000}).json()["items"],
                "agents": c.get("/api/agents").json()["items"],
                "tools": c.get("/api/tools").json()["items"],
            }
    return load


def test_clean_baseline(run):
    r = run("clean_baseline")
    assert r["events"] == 40 and r["summary"]["totals"]["providers"] == 5
    assert r["summary"]["risk"]["org_risk"] <= 24
    assert r["summary"]["alerts_by_severity"]["critical"] == 0


def test_quick_leak_is_exactly_52(run):
    """The headline demo: one leaked AWS secret, one unapproved tool, 12 events, risk exactly 52."""
    r = run("quick_leak")
    assert r["events"] == 12
    assert {f["rule_id"] for f in r["findings"]} == {"SEC_AWS_SECRET_KEY", "POLICY_UNSANCTIONED_TOOL"}
    assert [t["tool_id"] for t in r["tools"]] == ["python3|openai"]
    assert r["tools"][0]["risk"] == 52                                   # S = 54.0 + 4.5 = 58.5
    assert r["summary"]["risk"] == {"org_risk": 52, "band": "high", "compliance_score": 48}
    assert r["summary"]["alerts_by_severity"] == {"critical": 1, "high": 0, "medium": 0, "low": 1}


def test_full_demo(run):
    r = run("full_demo")
    s = r["summary"]
    assert r["events"] == 120
    assert s["totals"]["providers"] >= 8 and s["totals"]["tools"] >= 9
    assert s["totals"]["alerts_open"] >= 15 and s["alerts_by_severity"]["critical"] >= 3
    assert 60 <= s["risk"]["org_risk"] <= 100
    by_tool = {t["tool_id"]: t for t in r["tools"]}
    huggingface = [f for f in r["findings"] if f["tool_id"] == "curl|huggingface" and f["category"] != "policy"]
    assert huggingface == []                                              # its own token in its own header: no finding
    assert any(f["rule_id"] == "SEC_JWT" and f["location"]["field"] == "header:authorization"
               for f in r["findings"] if f["tool_id"] == "node|mistral")  # a foreign credential is one
    assert "browser|chatgpt_web" in by_tool and by_tool["browser|chatgpt_web"]["visibility"]["full"] == 0


def test_agent_attack(run):
    r = run("agent_attack")
    agent_findings = [f for f in r["findings"] if f["category"] == "agent"]
    used = {name for a in r["agents"] for name, cap in a["capabilities"].items() if cap["used"]}
    assert r["events"] == 30
    assert {"shell", "fs_read", "network", "sensitive_file"} <= used
    assert len(agent_findings) >= 4 and any(f["severity"] == "critical" for f in agent_findings)

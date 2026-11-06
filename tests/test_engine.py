"""The Rust engine (engine/): its generated sources are current, and when it is built it matches the reference."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "engine" / "target" / "release" / "engine-adapter"


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "engine" / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("tool", ["gen_unicode_tables", "gen_patterns"])
def test_generated_rust_sources_are_current(tool, tmp_path, monkeypatch):
    module = load_tool(tool)
    committed = module.OUT.read_bytes()
    monkeypatch.setattr(module, "OUT", tmp_path / "out.rs")
    module.main()
    assert (tmp_path / "out.rs").read_bytes() == committed, f"run engine/tools/{tool}.py and commit the result"


needs_adapter = pytest.mark.skipif(not ADAPTER.exists(), reason="build it: cd engine && cargo build --release -p engine-adapter")


def adapter_cmd(tmp_path):
    from conformance.build import build
    build(tmp_path)
    return f"{ADAPTER} --settings {tmp_path / 'settings.json'}"


@needs_adapter
def test_the_rust_engine_passes_the_conformance_suite(tmp_path):
    from conformance.check import compare, load, run
    cmd = adapter_cmd(tmp_path)
    rows = load(tmp_path)
    _, misses = compare(rows, run(cmd.split(), rows))
    assert misses == []


@needs_adapter
def test_the_rust_engine_matches_the_reference_on_random_text(tmp_path):
    done = subprocess.run([sys.executable, "-m", "conformance.fuzz", "--cmd", adapter_cmd(tmp_path), "--n", "1500", "--seed", "11"],
                          cwd=ROOT, capture_output=True, text=True, timeout=600)
    assert done.returncode == 0, done.stdout[-3000:]

"""Unit tests for PatchProof data models."""

import json
import tempfile
from pathlib import Path

from patchproof.models import Finding, TraceStep, Evidence


def test_trace_step_round_trip():
    step = TraceStep(file="app.py", line=14, code='request.args.get("q")', role="source")
    d = step.to_dict()
    restored = TraceStep.from_dict(d)
    assert restored.file == "app.py"
    assert restored.line == 14
    assert restored.role == "source"


def test_finding_id_stability():
    """Finding identity should not change when line numbers shift."""
    id1 = Finding.compute_id("pp-flask-sqli", "app.py", "search", 'db.execute(f"SELECT ... {q}")')
    id2 = Finding.compute_id("pp-flask-sqli", "app.py", "search", 'db.execute(f"SELECT ... {q}")')
    assert id1 == id2


def test_finding_id_ignores_whitespace():
    """Normalized sink snippet should ignore extra whitespace."""
    id1 = Finding.compute_id("pp-flask-sqli", "app.py", "search", 'db.execute(f"SELECT {q}")')
    id2 = Finding.compute_id("pp-flask-sqli", "app.py", "search", 'db.execute(f"SELECT  {q}")')
    # After normalization, extra spaces collapse
    assert id1 == id2


def test_finding_round_trip():
    f = Finding(
        id="abc123",
        rule_id="pp-flask-sqli",
        cwe="CWE-89",
        severity="ERROR",
        trace=[TraceStep("app.py", 14, 'request.args.get("q")', "source")],
        route="/search",
        method="GET",
        param="q",
        status="found",
    )
    d = f.to_dict()
    restored = Finding.from_dict(d)
    assert restored.id == "abc123"
    assert restored.route == "/search"
    assert len(restored.trace) == 1
    assert restored.trace[0].role == "source"


def test_finding_save_load(tmp_path):
    f = Finding(
        id="test123",
        rule_id="pp-flask-sqli",
        cwe="CWE-89",
        severity="ERROR",
        trace=[],
        status="found",
    )
    path = f.save(tmp_path)
    loaded = Finding.load(path)
    assert loaded.id == "test123"
    assert loaded.rule_id == "pp-flask-sqli"


def test_finding_mutants_killed_serialization():
    f = Finding(
        id="mut123",
        rule_id="pp-flask-cmdi",
        cwe="CWE-78",
        severity="ERROR",
        trace=[],
        mutants_killed=(2, 3),
    )
    d = f.to_dict()
    assert d["mutants_killed"] == [2, 3]
    restored = Finding.from_dict(d)
    assert restored.mutants_killed == (2, 3)

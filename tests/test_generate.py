"""Unit tests for test generation."""

import tempfile
from pathlib import Path

from patchproof.models import Finding, TraceStep
from patchproof.generate import generate_test


def test_generate_sqli_test(tmp_path):
    """Test that the SQLi template generates a valid test file."""
    finding = Finding(
        id="sqli001",
        rule_id="pp-flask-sqli",
        cwe="CWE-89",
        severity="ERROR",
        trace=[
            TraceStep("app.py", 14, 'request.args.get("q")', "source"),
            TraceStep("app.py", 18, 'db.execute(query)', "sink"),
        ],
        route="/search",
        method="GET",
        param="q",
    )

    # Use the project's actual templates and payloads directories
    project_root = Path(__file__).parent.parent
    templates_dir = project_root / "templates"
    payloads_dir = project_root / "payloads"

    if not templates_dir.exists() or not payloads_dir.exists():
        return  # Skip if not in project context

    result = generate_test(finding, templates_dir, payloads_dir, tmp_path)
    assert result is not None
    assert result.exists()
    content = result.read_text()
    assert "PP_CANARY_SQLI_8f2a" in content
    assert "def test_" in content
    assert "@pytest.mark.parametrize" in content

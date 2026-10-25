"""Stage 3: Generate regression tests from templates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from .models import Finding

console = Console()

# CWE to template name mapping
CWE_TEMPLATE_MAP = {
    "CWE-89": "test_sqli.py.j2",
    "CWE-78": "test_cmdi.py.j2",
    "CWE-22": "test_pathtraversal.py.j2",
    "CWE-918": "test_ssrf.py.j2",
}

# CWE to payload key mapping
CWE_PAYLOAD_MAP = {
    "CWE-89": "sqli",
    "CWE-78": "cmdi",
    "CWE-22": "pathtraversal",
    "CWE-918": "ssrf",
}


def load_payloads(payloads_dir: Path) -> dict[str, Any]:
    """Load payload banks from YAML."""
    payload_file = payloads_dir / "payloads.yml"
    if payload_file.exists():
        return yaml.safe_load(payload_file.read_text(encoding="utf-8"))
    return {}


def generate_test(
    finding: Finding,
    templates_dir: Path,
    payloads_dir: Path,
    output_dir: Path,
) -> Path | None:
    """Generate a pytest regression test for a finding."""
    cwe = finding.cwe
    template_name = CWE_TEMPLATE_MAP.get(cwe)
    if not template_name:
        console.print(f"[yellow]No template for {cwe}, skipping test generation[/yellow]")
        return None

    # Load payloads
    all_payloads = load_payloads(payloads_dir)
    payload_key = CWE_PAYLOAD_MAP.get(cwe, "")
    payload_bank = all_payloads.get(payload_key, {})

    # Setup Jinja2
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        keep_trailing_newline=True,
    )
    template = env.get_template(template_name)

    # Build template context
    source_step = next((s for s in finding.trace if s.role == "source"), None)
    sink_step = next((s for s in finding.trace if s.role == "sink"), None)

    context = {
        "finding": finding,
        "route": finding.route or "/",
        "method": (finding.method or "GET").lower(),
        "param": finding.param or "input",
        "payloads": payload_bank.get("payloads", []),
        "bypass_payloads": payload_bank.get("bypass_payloads", []),
        "canary": payload_bank.get("canary", "PP_CANARY"),
        "source_file": source_step.file if source_step else "",
        "source_line": source_step.line if source_step else 0,
        "source_code": source_step.code if source_step else "",
        "sink_file": sink_step.file if sink_step else "",
        "sink_line": sink_step.line if sink_step else 0,
        "sink_code": sink_step.code if sink_step else "",
    }

    # Render
    test_code = template.render(**context)

    # Write output
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_rule = finding.rule_id.replace("-", "_").replace(".", "_")
    test_filename = f"test_{safe_rule}_{finding.id}.py"
    test_path = output_dir / test_filename
    test_path.write_text(test_code, encoding="utf-8")

    finding.test_path = str(test_path)
    console.print(f"  [green]Generated:[/green] {test_path.name}")
    return test_path


def generate_all_tests(
    findings: list[Finding],
    templates_dir: Path,
    payloads_dir: Path,
    output_dir: Path,
) -> list[Path]:
    """Generate regression tests for all findings."""
    console.print(f"\n[bold blue]Generating tests for {len(findings)} finding(s)...[/bold blue]")
    paths = []
    for finding in findings:
        path = generate_test(finding, templates_dir, payloads_dir, output_dir)
        if path:
            paths.append(path)
    return paths

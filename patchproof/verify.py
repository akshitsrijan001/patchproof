"""Stage 6: Verify fixes — rescan, finding identity diff, suite check."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

from .models import Finding
from .scan import run_semgrep, parse_semgrep_results

console = Console()


def rescan_and_compare(
    finding: Finding,
    target_dir: Path,
    rules_dir: Path,
    output_dir: Path,
    before_results: dict[str, Any] | None = None,
) -> bool:
    """Rescan after fix and compare findings."""
    console.print(f"\n[bold blue]Rescanning for {finding.rule_id}...[/bold blue]")

    after_dir = output_dir / "after"
    after_results = run_semgrep(target_dir, rules_dir, after_dir)

    # Save after results
    after_json = after_dir / "scan_results.json"

    # Check if the specific finding is gone
    after_findings = parse_semgrep_results(after_results)

    still_present = any(
        f["rule_id"] == finding.rule_id
        for f in after_findings
    )

    if still_present:
        console.print(f"  [bold red]Finding still present after fix![/bold red]")
        finding.sarif_after = True
        return False
    else:
        console.print(f"  [bold green]Finding resolved after fix[/bold green]")
        finding.sarif_after = False
        return True


def run_existing_tests(project_root: Path) -> tuple[bool, str]:
    """Run existing test suite to check for regressions."""
    console.print(f"\n[bold blue]Running existing test suite...[/bold blue]")

    test_dir = project_root / "tests"
    if not test_dir.exists() or not any(test_dir.glob("test_*.py")):
        console.print("  [yellow]No existing test suite found[/yellow]")
        return True, "No existing tests"

    result = subprocess.run(
        ["python", "-m", "pytest", str(test_dir), "-v", "--tb=short"],
        capture_output=True,
        text=True,
        cwd=str(project_root),
        timeout=120,
    )

    output = result.stdout + "\n" + result.stderr
    passed = result.returncode == 0

    if passed:
        console.print("  [green]Existing tests still pass[/green]")
    else:
        console.print("  [red]Existing tests failed — regression detected![/red]")

    return passed, output

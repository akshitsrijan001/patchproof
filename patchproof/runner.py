"""Stage 4 & 6: Run pytest tests and capture evidence."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from rich.console import Console

from .models import Finding

console = Console(legacy_windows=False)


def run_test(
    test_path: Path,
    project_root: Path,
    label: str = "test",
) -> dict[str, Any]:
    """Run a pytest test file and capture the result."""
    console.print(f"  Running {label}: {test_path.name}...")

    cmd = [
        sys.executable, "-m", "pytest",
        str(test_path),
        "-v",
        "--tb=short",
        "--no-header",
    ]

    start = time.time()
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(project_root),
        timeout=60,
    )
    elapsed = time.time() - start

    output = result.stdout + "\n" + result.stderr
    passed = result.returncode == 0
    failed = result.returncode != 0

    status_icon = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
    console.print(f"    {status_icon} ({elapsed:.1f}s)")

    return {
        "exit_code": result.returncode,
        "output": output,
        "passed": passed,
        "failed": failed,
        "elapsed": elapsed,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def red_run(finding: Finding, project_root: Path) -> dict[str, Any]:
    """Stage 4: Red run — test must FAIL on vulnerable code (proving exploitability)."""
    console.print(f"\n[bold red]RED RUN[/bold red] — {finding.rule_id}")

    if not finding.test_path:
        console.print("  [yellow]No test generated, skipping red run[/yellow]")
        finding.status = "unconfirmed"
        return {"skipped": True, "reason": "no test"}

    test_path = Path(finding.test_path)
    if not test_path.exists():
        console.print("  [yellow]Test file not found[/yellow]")
        finding.status = "unconfirmed"
        return {"skipped": True, "reason": "test file missing"}

    result = run_test(test_path, project_root, label="red run")
    finding.red = result

    if result["failed"]:
        # Test FAILED on vulnerable code — this proves the bug is real
        console.print("  [bold green]Exploitability confirmed![/bold green] Test fails on vulnerable code.")
        finding.status = "confirmed"
    else:
        # Test PASSED on vulnerable code — cannot prove exploitability
        console.print("  [bold yellow]Unconfirmed:[/bold yellow] test passed on vulnerable code.")
        console.print("    The payload bank or canary may have missed. Finding is NOT dismissed.")
        finding.status = "unconfirmed"

    return result


def green_run(finding: Finding, project_root: Path) -> dict[str, Any]:
    """Stage 6: Green run — test must PASS after the fix."""
    console.print(f"\n[bold green]GREEN RUN[/bold green] — {finding.rule_id}")

    if not finding.test_path:
        return {"skipped": True, "reason": "no test"}

    test_path = Path(finding.test_path)
    result = run_test(test_path, project_root, label="green run")
    finding.green = result

    if result["passed"]:
        console.print("  [bold green]Fix verified![/bold green] Test passes after fix.")
    else:
        console.print("  [bold red]Fix rejected![/bold red] Test still fails after fix.")
        finding.status = "fix_rejected"

    return result

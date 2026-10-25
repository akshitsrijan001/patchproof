"""Stage 1: Run Semgrep and parse results."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console(legacy_windows=False)


def find_semgrep() -> str:
    """Locate the semgrep executable."""
    which_path = shutil.which("semgrep")
    if which_path:
        return which_path
    venv_bin = Path(sys.executable).parent
    for name in ["semgrep.exe", "semgrep"]:
        candidate = venv_bin / name
        if candidate.exists():
            return str(candidate)
    return "semgrep"


def run_semgrep(
    target_dir: Path,
    rules_dir: Path,
    output_dir: Path,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Run Semgrep with PatchProof rules and return parsed JSON results."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_output = output_dir / "scan_results.json"
    sarif_output = output_dir / "scan_results.sarif"

    semgrep_bin = find_semgrep()

    cmd = [
        semgrep_bin, "scan",
        "--config", str(rules_dir),
        "--json",
        f"--output={json_output}",
        "--dataflow-traces",
        "--no-git-ignore",
        "--metrics=off",
        "--disable-version-check",
        str(target_dir),
    ]
    if extra_args:
        cmd.extend(extra_args)

    console.print(f"[bold blue]Running Semgrep scan...[/bold blue]")
    console.print(f"  Target: {target_dir}")
    console.print(f"  Rules:  {rules_dir}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(target_dir.parent),
    )

    # Semgrep exits with 1 when findings exist, which is expected
    if result.returncode not in (0, 1):
        console.print(f"[bold red]Semgrep error:[/bold red] {result.stderr}")
        raise RuntimeError(f"Semgrep failed with exit code {result.returncode}: {result.stderr}")

    # Also run SARIF output
    sarif_cmd = [
        semgrep_bin, "scan",
        "--config", str(rules_dir),
        "--sarif",
        f"--output={sarif_output}",
        "--dataflow-traces",
        "--no-git-ignore",
        "--metrics=off",
        "--disable-version-check",
        str(target_dir),
    ]
    subprocess.run(
        sarif_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(target_dir.parent),
    )

    if json_output.exists():
        results = json.loads(json_output.read_text(encoding="utf-8"))
        num_findings = len(results.get("results", []))
        console.print(f"[bold green]Found {num_findings} finding(s)[/bold green]")
        return results
    else:
        console.print("[bold yellow]No Semgrep output file generated[/bold yellow]")
        return {"results": []}


def parse_semgrep_results(results: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract relevant finding data from Semgrep JSON output."""
    findings = []
    for r in results.get("results", []):
        raw_id = r.get("check_id", "")
        rule_id = raw_id.split(".")[-1] if "." in raw_id else raw_id
        finding = {
            "rule_id": rule_id,
            "path": r.get("path", ""),
            "start_line": r.get("start", {}).get("line", 0),
            "end_line": r.get("end", {}).get("line", 0),
            "message": r.get("extra", {}).get("message", ""),
            "severity": r.get("extra", {}).get("severity", "WARNING"),
            "metadata": r.get("extra", {}).get("metadata", {}),
            "code": r.get("extra", {}).get("lines", ""),
            "dataflow_trace": r.get("extra", {}).get("dataflow_trace"),
        }
        findings.append(finding)
    return findings

"""Stage 1: Run Semgrep and parse results."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


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

    cmd = [
        "semgrep", "scan",
        "--config", str(rules_dir),
        "--json",
        f"--output={json_output}",
        "--dataflow-traces",
        "--no-git-ignore",
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
        cwd=str(target_dir.parent),
    )

    # Semgrep exits with 1 when findings exist, which is expected
    if result.returncode not in (0, 1):
        console.print(f"[bold red]Semgrep error:[/bold red] {result.stderr}")
        raise RuntimeError(f"Semgrep failed with exit code {result.returncode}: {result.stderr}")

    # Also run SARIF output
    sarif_cmd = [
        "semgrep", "scan",
        "--config", str(rules_dir),
        "--sarif",
        f"--output={sarif_output}",
        "--dataflow-traces",
        "--no-git-ignore",
        str(target_dir),
    ]
    subprocess.run(sarif_cmd, capture_output=True, text=True, cwd=str(target_dir.parent))

    if json_output.exists():
        results = json.loads(json_output.read_text())
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
        finding = {
            "rule_id": r.get("check_id", ""),
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

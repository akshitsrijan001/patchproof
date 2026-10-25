"""PatchProof CLI — scan, gen, verify, report, demo."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="patchproof",
    help="Security Rules That Generate Regression Tests",
    rich_markup_mode="rich",
)
console = Console()

# Default paths relative to project root
DEFAULT_TARGET = "target/vuln_app"
DEFAULT_RULES = "rules"
DEFAULT_TEMPLATES = "templates"
DEFAULT_PAYLOADS = "payloads"
DEFAULT_FIXES = "fixes"
DEFAULT_OUTPUT = ".patchproof"
DEFAULT_GENERATED = "generated_tests"
DEFAULT_REPORTS = "reports"


def get_project_root() -> Path:
    """Find the PatchProof project root."""
    # Look for pyproject.toml going up from cwd
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        if (parent / "pyproject.toml").exists() and (parent / "rules").exists():
            return parent
    return cwd


@app.command()
def scan(
    target: str = typer.Option(DEFAULT_TARGET, help="Target directory to scan"),
    rules: str = typer.Option(DEFAULT_RULES, help="Semgrep rules directory"),
    output: str = typer.Option(DEFAULT_OUTPUT, help="Output directory"),
):
    """Stage 1: Run Semgrep scan on target code."""
    from .scan import run_semgrep, parse_semgrep_results
    from .triage import triage_all

    root = get_project_root()
    target_dir = root / target
    rules_dir = root / rules
    output_dir = root / output

    console.print(Panel("[bold]Stage 1: Scan[/bold]", style="blue"))

    results = run_semgrep(target_dir, rules_dir, output_dir / "before")
    raw_findings = parse_semgrep_results(results)

    console.print(Panel("[bold]Stage 2: Triage[/bold]", style="blue"))
    findings = triage_all(raw_findings, root)

    # Save findings
    for finding in findings:
        finding.save(output_dir)

    # Save summary
    summary = {"findings": [f.to_dict() for f in findings], "count": len(findings)}
    summary_path = output_dir / "findings.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    console.print(f"\n[bold green]Saved {len(findings)} finding(s) to {summary_path}[/bold green]")


@app.command()
def gen(
    output: str = typer.Option(DEFAULT_OUTPUT, help="PatchProof output directory"),
    templates: str = typer.Option(DEFAULT_TEMPLATES, help="Templates directory"),
    payloads: str = typer.Option(DEFAULT_PAYLOADS, help="Payloads directory"),
    generated: str = typer.Option(DEFAULT_GENERATED, help="Generated tests output"),
):
    """Stage 3: Generate regression tests from findings."""
    from .models import Finding
    from .generate import generate_all_tests

    root = get_project_root()
    output_dir = root / output
    templates_dir = root / templates
    payloads_dir = root / payloads
    generated_dir = root / generated

    console.print(Panel("[bold]Stage 3: Generate Tests[/bold]", style="blue"))

    # Load findings
    findings_path = output_dir / "findings.json"
    if not findings_path.exists():
        console.print("[red]No findings found. Run 'patchproof scan' first.[/red]")
        raise typer.Exit(1)

    data = json.loads(findings_path.read_text())
    findings = [Finding.from_dict(f) for f in data["findings"]]

    paths = generate_all_tests(findings, templates_dir, payloads_dir, generated_dir)

    # Update findings
    data["findings"] = [f.to_dict() for f in findings]
    findings_path.write_text(json.dumps(data, indent=2))
    console.print(f"\n[bold green]Generated {len(paths)} test(s)[/bold green]")


@app.command()
def red(
    output: str = typer.Option(DEFAULT_OUTPUT, help="PatchProof output directory"),
):
    """Stage 4: Red run — prove exploitability on vulnerable code."""
    from .models import Finding
    from .runner import red_run

    root = get_project_root()
    output_dir = root / output

    console.print(Panel("[bold]Stage 4: Red Run[/bold]", style="red"))

    findings_path = output_dir / "findings.json"
    data = json.loads(findings_path.read_text())
    findings = [Finding.from_dict(f) for f in data["findings"]]

    for finding in findings:
        red_run(finding, root)

    data["findings"] = [f.to_dict() for f in findings]
    findings_path.write_text(json.dumps(data, indent=2))


@app.command()
def fix(
    output: str = typer.Option(DEFAULT_OUTPUT, help="PatchProof output directory"),
    fixes: str = typer.Option(DEFAULT_FIXES, help="Fixes directory"),
):
    """Stage 5: Apply fixes."""
    from .models import Finding
    from .fix import apply_fix_for_finding

    root = get_project_root()
    output_dir = root / output
    fixes_dir = root / fixes

    console.print(Panel("[bold]Stage 5: Apply Fixes[/bold]", style="yellow"))

    findings_path = output_dir / "findings.json"
    data = json.loads(findings_path.read_text())
    findings = [Finding.from_dict(f) for f in data["findings"]]

    for finding in findings:
        if finding.status == "confirmed":
            success, diff = apply_fix_for_finding(finding, fixes_dir, root)
            if success:
                finding.status = "fixed"

    data["findings"] = [f.to_dict() for f in findings]
    findings_path.write_text(json.dumps(data, indent=2))


@app.command()
def verify(
    output: str = typer.Option(DEFAULT_OUTPUT, help="PatchProof output directory"),
    rules: str = typer.Option(DEFAULT_RULES, help="Semgrep rules directory"),
    fixes: str = typer.Option(DEFAULT_FIXES, help="Fixes directory"),
):
    """Stage 6: Verify fixes — green run + rescan."""
    from .models import Finding
    from .runner import green_run
    from .verify import rescan_and_compare, run_existing_tests
    from .mutate import run_sensitivity_check

    root = get_project_root()
    output_dir = root / output
    rules_dir = root / rules
    fixes_dir = root / fixes
    target_dir = root / DEFAULT_TARGET

    console.print(Panel("[bold]Stage 6: Verify[/bold]", style="green"))

    findings_path = output_dir / "findings.json"
    data = json.loads(findings_path.read_text())
    findings = [Finding.from_dict(f) for f in data["findings"]]

    for finding in findings:
        if finding.status in ("fixed", "confirmed"):
            green_run(finding, root)
            rescan_and_compare(finding, target_dir, rules_dir, output_dir)
            run_sensitivity_check(finding, fixes_dir, root)

    # Run existing test suite
    suite_passed, _ = run_existing_tests(root)

    data["findings"] = [f.to_dict() for f in findings]
    findings_path.write_text(json.dumps(data, indent=2))


@app.command()
def report(
    output: str = typer.Option(DEFAULT_OUTPUT, help="PatchProof output directory"),
    reports: str = typer.Option(DEFAULT_REPORTS, help="Reports output directory"),
    templates: str = typer.Option(DEFAULT_TEMPLATES, help="Templates directory"),
):
    """Stage 7: Generate evidence reports."""
    from .models import Finding, Evidence
    from .report import generate_finding_report, generate_summary_report, generate_html_report

    root = get_project_root()
    output_dir = root / output
    reports_dir = root / reports
    templates_dir = root / templates

    console.print(Panel("[bold]Stage 7: Report[/bold]", style="magenta"))

    findings_path = output_dir / "findings.json"
    data = json.loads(findings_path.read_text())
    findings = [Finding.from_dict(f) for f in data["findings"]]

    evidences = []
    for finding in findings:
        ev = Evidence(finding=finding)
        generate_finding_report(ev, reports_dir)
        evidences.append(ev)

    generate_summary_report(evidences, reports_dir)
    generate_html_report(evidences, templates_dir, reports_dir)

    console.print(f"\n[bold green]Reports generated in {reports_dir}[/bold green]")


@app.command()
def demo(
    only: Optional[str] = typer.Option(None, help="Run demo for only one vuln: sqli, cmdi, pathtraversal"),
):
    """Run the full PatchProof demo on the bundled vulnerable app."""
    from .models import Finding, Evidence
    from .scan import run_semgrep, parse_semgrep_results
    from .triage import triage_all
    from .generate import generate_all_tests
    from .runner import red_run, green_run
    from .fix import apply_fix_for_finding, revert_fix_for_finding
    from .verify import rescan_and_compare, run_existing_tests
    from .mutate import run_sensitivity_check
    from .report import generate_finding_report, generate_summary_report, generate_html_report

    root = get_project_root()
    target_dir = root / DEFAULT_TARGET
    rules_dir = root / DEFAULT_RULES
    output_dir = root / DEFAULT_OUTPUT
    templates_dir = root / DEFAULT_TEMPLATES
    payloads_dir = root / DEFAULT_PAYLOADS
    fixes_dir = root / DEFAULT_FIXES
    generated_dir = root / DEFAULT_GENERATED
    reports_dir = root / DEFAULT_REPORTS

    console.print(Panel(
        "[bold white on blue] PatchProof Demo [/bold white on blue]\n"
        "A scanner tells you something looks wrong.\n"
        "PatchProof [bold]proves[/bold] it is wrong, proves the fix works,\n"
        "and makes sure it never comes back.",
        title="🛡️",
        border_style="blue",
    ))

    start_time = time.time()

    # Stage 1: Scan
    console.print(Panel("[bold]Stage 1: Scan[/bold]", style="blue"))
    results = run_semgrep(target_dir, rules_dir, output_dir / "before")
    raw_findings = parse_semgrep_results(results)

    # Stage 2: Triage
    console.print(Panel("[bold]Stage 2: Triage[/bold]", style="blue"))
    findings = triage_all(raw_findings, root)

    # Filter if --only
    if only:
        rule_map = {
            "sqli": "pp-flask-sqli",
            "cmdi": "pp-flask-cmdi",
            "pathtraversal": "pp-flask-pathtraversal",
        }
        target_rule = rule_map.get(only)
        if target_rule:
            findings = [f for f in findings if f.rule_id == target_rule]
            console.print(f"[yellow]Filtered to {len(findings)} finding(s) for {only}[/yellow]")

    if not findings:
        console.print("[red]No findings to process.[/red]")
        raise typer.Exit(1)

    # Stage 3: Generate tests
    console.print(Panel("[bold]Stage 3: Generate Tests[/bold]", style="blue"))
    test_paths = generate_all_tests(findings, templates_dir, payloads_dir, generated_dir)

    # Stage 4: Red run
    console.print(Panel("[bold]Stage 4: Red Run (Proof of Exploitability)[/bold]", style="red"))
    for finding in findings:
        red_run(finding, root)

    # Stage 5: Fix
    console.print(Panel("[bold]Stage 5: Apply Fixes[/bold]", style="yellow"))
    diffs: dict[str, str] = {}
    for finding in findings:
        if finding.status == "confirmed":
            success, diff = apply_fix_for_finding(finding, fixes_dir, root)
            if success:
                diffs[finding.id] = diff

    # Stage 6: Verify
    console.print(Panel("[bold]Stage 6: Verify (Green Run + Rescan)[/bold]", style="green"))
    for finding in findings:
        if finding.status in ("confirmed", "fixed"):
            green_run(finding, root)
            rescan_and_compare(finding, target_dir, rules_dir, output_dir)
            if finding.green and finding.green.get("passed") and finding.sarif_after is False:
                finding.status = "fixed"

    # Sensitivity check
    console.print(Panel("[bold]Sensitivity Check[/bold]", style="cyan"))
    for finding in findings:
        run_sensitivity_check(finding, fixes_dir, root)

    # Suite check
    suite_passed, suite_output = run_existing_tests(root)

    # Stage 7: Report
    console.print(Panel("[bold]Stage 7: Evidence Reports[/bold]", style="magenta"))
    evidences = []
    for finding in findings:
        ev = Evidence(
            finding=finding,
            diff_patch=diffs.get(finding.id, ""),
            suite_passed=suite_passed,
        )
        generate_finding_report(ev, reports_dir)
        evidences.append(ev)

    generate_summary_report(evidences, reports_dir)
    generate_html_report(evidences, templates_dir, reports_dir)

    # Save findings
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {"findings": [f.to_dict() for f in findings], "count": len(findings)}
    (output_dir / "findings.json").write_text(json.dumps(summary, indent=2))

    elapsed = time.time() - start_time

    # Final summary
    console.print("\n")
    table = Table(title="PatchProof Results", show_header=True)
    table.add_column("Rule", style="cyan")
    table.add_column("CWE")
    table.add_column("Status", justify="center")
    table.add_column("Red", justify="center")
    table.add_column("Green", justify="center")
    table.add_column("Scanner", justify="center")
    table.add_column("Sensitivity", justify="center")

    for f in findings:
        status_map = {
            "fixed": "[green]FIXED ✅[/green]",
            "fix_rejected": "[red]REJECTED ❌[/red]",
            "unconfirmed": "[yellow]UNCONFIRMED ⚠️[/yellow]",
            "confirmed": "[blue]CONFIRMED[/blue]",
        }
        status = status_map.get(f.status, f.status)
        red_str = "[red]FAIL ✗[/red]" if f.red and f.red.get("failed") else "—"
        green_str = "[green]PASS ✓[/green]" if f.green and f.green.get("passed") else "—"
        scanner = "[green]Resolved ✅[/green]" if f.sarif_after is False else "—"
        sens = f"{f.mutants_killed[0]}/{f.mutants_killed[1]}" if f.mutants_killed else "—"
        table.add_row(f.rule_id, f.cwe, status, red_str, green_str, scanner, sens)

    console.print(table)
    console.print(f"\n[bold]Completed in {elapsed:.1f}s[/bold]")
    console.print(f"Reports: {reports_dir}")


if __name__ == "__main__":
    app()

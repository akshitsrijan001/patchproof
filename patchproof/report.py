"""Stage 7: Generate evidence reports in Markdown and HTML."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from .models import Finding, Evidence

console = Console()


def generate_finding_report(evidence: Evidence, output_dir: Path) -> Path:
    """Generate a Markdown report for a single finding."""
    f = evidence.finding
    output_dir.mkdir(parents=True, exist_ok=True)

    # Status badge
    status_map = {
        "fixed": "✅ FIXED AND VERIFIED",
        "fix_rejected": "❌ FIX REJECTED",
        "unconfirmed": "⚠️ UNCONFIRMED",
        "confirmed": "🔍 CONFIRMED (pending fix)",
        "found": "📋 FOUND",
    }
    status_badge = status_map.get(f.status, f.status.upper())

    lines = []
    lines.append(f"# {f.rule_id} — {f.cwe}")
    lines.append(f"\n**Status:** {status_badge}")
    lines.append(f"**Severity:** {f.severity}")
    lines.append(f"**Finding ID:** `{f.id}`")
    lines.append("")

    # 1. Summary
    lines.append("## 1. Summary")
    lines.append(f"\nRule `{f.rule_id}` detected a **{f.cwe}** vulnerability.")
    if f.route:
        lines.append(f"Entry point: `{f.method} {f.route}` via parameter `{f.param}`.")
    lines.append("")

    # 2. Root Cause
    lines.append("## 2. Root Cause (Source → Sink)")
    lines.append("")
    for step in f.trace:
        icon = {"source": "🟢", "propagation": "🔵", "sink": "🔴"}.get(step.role, "⚪")
        lines.append(f"- {icon} **{step.role.capitalize()}** — `{step.file}:{step.line}`")
        lines.append(f"  ```python")
        lines.append(f"  {step.code}")
        lines.append(f"  ```")
    lines.append("")

    # 3. Why it is exploitable
    lines.append("## 3. Why It Is Exploitable")
    lines.append(f"\nUser input enters at the source and flows unvalidated to the sink,")
    lines.append(f"where it is used in a dangerous operation without proper sanitization.")
    lines.append("")

    # 4. Generated test
    lines.append("## 4. Generated Regression Test")
    if f.test_path:
        test_path = Path(f.test_path)
        if test_path.exists():
            lines.append(f"\n```python")
            lines.append(test_path.read_text(encoding="utf-8"))
            lines.append(f"```")
    lines.append("")

    # 5. Red run
    lines.append("## 5. Red Run (Vulnerable Code)")
    if f.red:
        exit_code = f.red.get("exit_code", "N/A")
        lines.append(f"\n**Exit code:** {exit_code} ({'FAIL ✗' if exit_code != 0 else 'PASS ✓'})")
        lines.append(f"```")
        lines.append(f.red.get("output", "No output captured"))
        lines.append(f"```")
    else:
        lines.append("\n*Not run*")
    lines.append("")

    # 6. Fix
    lines.append("## 6. Fix Applied")
    if evidence.diff_patch:
        lines.append(f"\n```diff")
        lines.append(evidence.diff_patch)
        lines.append(f"```")
    else:
        lines.append("\n*No fix applied*")
    lines.append("")

    # 7. Green run
    lines.append("## 7. Green Run (Fixed Code)")
    if f.green:
        exit_code = f.green.get("exit_code", "N/A")
        lines.append(f"\n**Exit code:** {exit_code} ({'PASS ✓' if exit_code == 0 else 'FAIL ✗'})")
        lines.append(f"```")
        lines.append(f.green.get("output", "No output captured"))
        lines.append(f"```")
    else:
        lines.append("\n*Not run*")
    lines.append("")

    # 8. Scanner diff
    lines.append("## 8. Scanner Diff")
    lines.append(f"\n- **Before fix:** {'Finding present' if f.sarif_before else 'No finding'}")
    lines.append(f"- **After fix:** {'Finding present ❌' if f.sarif_after else 'Finding resolved ✅' if f.sarif_after is not None else 'Not scanned'}")
    lines.append("")

    # 9. Suite check
    lines.append("## 9. Existing Test Suite")
    if evidence.suite_passed is not None:
        lines.append(f"\n{'✅ All existing tests pass' if evidence.suite_passed else '❌ Regression detected'}")
    else:
        lines.append("\n*Not checked*")
    lines.append("")

    # 10. Sensitivity score
    lines.append("## 10. Sensitivity Score")
    if f.mutants_killed is not None:
        killed, total = f.mutants_killed
        lines.append(f"\n**{killed}/{total}** mutants killed")
        for mr in evidence.mutant_results:
            icon = "✅" if mr.get("status") == "killed" else "❌"
            lines.append(f"- {icon} `{mr.get('mutant', 'unknown')}`: {mr.get('status', 'unknown')}")
    else:
        lines.append("\n*No mutants tested*")
    lines.append("")

    # 11. Reproduce
    lines.append("## 11. Reproduce It Yourself")
    lines.append(f"\n```bash")
    lines.append(f"# 1. Run the scan")
    lines.append(f"patchproof scan target/vuln_app")
    lines.append(f"# 2. Generate and run tests (red)")
    lines.append(f"patchproof gen")
    lines.append(f"# 3. Apply fix and verify (green)")
    lines.append(f"patchproof verify")
    lines.append(f"```")
    lines.append("")

    # Write report
    report_path = output_dir / f"report-{f.id}.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"  [green]Report:[/green] {report_path.name}")
    return report_path


def generate_summary_report(evidences: list[Evidence], output_dir: Path) -> Path:
    """Generate a summary report across all findings."""
    output_dir.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append("# PatchProof — Verification Summary")
    lines.append("")
    lines.append("| # | Rule | CWE | Status | Red | Green | Scanner | Sensitivity |")
    lines.append("|---|------|-----|--------|-----|-------|---------|-------------|")

    for i, ev in enumerate(evidences, 1):
        f = ev.finding
        status_map = {
            "fixed": "✅ Fixed",
            "fix_rejected": "❌ Rejected",
            "unconfirmed": "⚠️ Unconfirmed",
            "confirmed": "🔍 Confirmed",
            "found": "📋 Found",
        }
        status = status_map.get(f.status, f.status)
        red = "FAIL ✗" if f.red and f.red.get("failed") else ("PASS" if f.red else "—")
        green = "PASS ✓" if f.green and f.green.get("passed") else ("FAIL" if f.green else "—")
        scanner = "Resolved ✅" if f.sarif_after is False else ("Present ❌" if f.sarif_after else "—")
        sensitivity = f"{f.mutants_killed[0]}/{f.mutants_killed[1]}" if f.mutants_killed else "—"
        lines.append(f"| {i} | `{f.rule_id}` | {f.cwe} | {status} | {red} | {green} | {scanner} | {sensitivity} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Timeline strip for each finding
    lines.append("## Timeline")
    lines.append("")
    for ev in evidences:
        f = ev.finding
        stages = ["📡 Scan"]
        if f.red:
            stages.append("🔴 Red")
        if ev.diff_patch:
            stages.append("🔧 Fix")
        if f.green:
            stages.append("🟢 Green")
        if f.sarif_after is not None:
            stages.append("🔍 Rescan")
        lines.append(f"**{f.rule_id}:** {' → '.join(stages)}")
        lines.append("")

    # Evidence integrity
    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by PatchProof v0.1.0*")

    report_path = output_dir / "SUMMARY.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"  [green]Summary:[/green] {report_path.name}")
    return report_path


def generate_html_report(evidences: list[Evidence], templates_dir: Path, output_dir: Path) -> Path:
    """Generate an HTML evidence report."""
    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        keep_trailing_newline=True,
    )

    try:
        template = env.get_template("report.html.j2")
    except Exception:
        # Fallback: generate basic HTML
        return _generate_basic_html(evidences, output_dir)

    html = template.render(evidences=evidences)
    html_path = output_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")
    console.print(f"  [green]HTML Report:[/green] {html_path.name}")
    return html_path


def _generate_basic_html(evidences: list[Evidence], output_dir: Path) -> Path:
    """Generate a basic HTML report without templates."""
    html_parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'>",
        "<title>PatchProof Report</title>",
        "<style>",
        "body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }",
        ".badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: bold; }",
        ".fixed { background: #d4edda; color: #155724; }",
        ".rejected { background: #f8d7da; color: #721c24; }",
        ".unconfirmed { background: #fff3cd; color: #856404; }",
        "pre { background: #f6f8fa; padding: 1rem; overflow-x: auto; border-radius: 6px; }",
        "table { border-collapse: collapse; width: 100%; }",
        "th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; }",
        "th { background: #f6f8fa; }",
        ".timeline { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }",
        ".timeline-step { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }",
        ".step-scan { background: #cce5ff; } .step-red { background: #f8d7da; }",
        ".step-fix { background: #fff3cd; } .step-green { background: #d4edda; }",
        ".step-rescan { background: #d1ecf1; }",
        "details { margin: 1rem 0; } summary { cursor: pointer; font-weight: bold; }",
        "</style></head><body>",
        "<h1>🛡️ PatchProof — Verification Report</h1>",
    ]

    # Summary table
    html_parts.append("<h2>Summary</h2><table>")
    html_parts.append("<tr><th>#</th><th>Rule</th><th>CWE</th><th>Status</th><th>Red</th><th>Green</th><th>Scanner</th><th>Sensitivity</th></tr>")

    for i, ev in enumerate(evidences, 1):
        f = ev.finding
        badge_class = {"fixed": "fixed", "fix_rejected": "rejected", "unconfirmed": "unconfirmed"}.get(f.status, "")
        status_text = {"fixed": "FIXED ✅", "fix_rejected": "REJECTED ❌", "unconfirmed": "UNCONFIRMED ⚠️"}.get(f.status, f.status.upper())
        red = "FAIL ✗" if f.red and f.red.get("failed") else "—"
        green = "PASS ✓" if f.green and f.green.get("passed") else "—"
        scanner = "Resolved ✅" if f.sarif_after is False else ("Present ❌" if f.sarif_after else "—")
        sensitivity = f"{f.mutants_killed[0]}/{f.mutants_killed[1]}" if f.mutants_killed else "—"
        html_parts.append(f"<tr><td>{i}</td><td><code>{f.rule_id}</code></td><td>{f.cwe}</td><td><span class='badge {badge_class}'>{status_text}</span></td><td>{red}</td><td>{green}</td><td>{scanner}</td><td>{sensitivity}</td></tr>")

    html_parts.append("</table>")

    # Per-finding details
    for ev in evidences:
        f = ev.finding
        html_parts.append(f"<hr><h2>{f.rule_id} — {f.cwe}</h2>")

        # Timeline
        html_parts.append("<div class='timeline'>")
        html_parts.append("<span class='timeline-step step-scan'>📡 Scan</span><span>→</span>")
        if f.red:
            html_parts.append("<span class='timeline-step step-red'>🔴 Red</span><span>→</span>")
        if ev.diff_patch:
            html_parts.append("<span class='timeline-step step-fix'>🔧 Fix</span><span>→</span>")
        if f.green:
            html_parts.append("<span class='timeline-step step-green'>🟢 Green</span><span>→</span>")
        if f.sarif_after is not None:
            html_parts.append("<span class='timeline-step step-rescan'>🔍 Rescan</span>")
        html_parts.append("</div>")

        # Root cause
        html_parts.append("<h3>Root Cause</h3>")
        for step in f.trace:
            icon = {"source": "🟢", "propagation": "🔵", "sink": "🔴"}.get(step.role, "⚪")
            html_parts.append(f"<p>{icon} <strong>{step.role.capitalize()}</strong> — <code>{step.file}:{step.line}</code></p>")
            html_parts.append(f"<pre>{step.code}</pre>")

        # Red run
        if f.red:
            html_parts.append("<details><summary>🔴 Red Run Output</summary>")
            html_parts.append(f"<pre>{f.red.get('output', '')}</pre></details>")

        # Fix
        if ev.diff_patch:
            html_parts.append("<details open><summary>🔧 Fix Diff</summary>")
            html_parts.append(f"<pre>{ev.diff_patch}</pre></details>")

        # Green run
        if f.green:
            html_parts.append("<details><summary>🟢 Green Run Output</summary>")
            html_parts.append(f"<pre>{f.green.get('output', '')}</pre></details>")

    html_parts.append("<hr><p><em>Generated by PatchProof v0.1.0</em></p></body></html>")

    html_path = output_dir / "report.html"
    html_path.write_text("\n".join(html_parts), encoding="utf-8")
    return html_path

"""Stage 7: Generate evidence reports in Markdown and HTML."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from .models import Finding, Evidence

console = Console(legacy_windows=False)

CWE_EXPLANATIONS = {
    "CWE-89": {
        "name": "SQL Injection (SQLi)",
        "category": "Injection",
        "description": "User input from the HTTP query string is directly concatenated into a dynamic SQL query without sanitization or parameter binding.",
        "impact": "Database compromise: attackers can extract confidential records (canary row), bypass authentication, or modify tables.",
        "canary": "PP_CANARY_SQLI_8f2a",
        "canary_desc": "A canary row with name 'PP_CANARY_SQLI_8f2a' seeded into the users table with role 'canary'.",
        "exploit_payload": "' OR '1'='1' --",
        "exploit_mechanism": "Injects a tautology ('1'='1') that causes the WHERE condition to evaluate to true for every row, leaking all records including secret canary rows.",
        "solution_title": "Parameterized Queries (Prepared Statements)",
        "solution_mechanism": "Replaces query string formatting with parameterized placeholders ('?'). The SQL statement structure is parsed and compiled by the database engine independently from data values, rendering input characters syntactically harmless.",
        "bad_fix_title": "Naive Comment / Quote Blacklisting",
        "bad_fix_mechanism": "Developers often mistakenly try to strip comment markers (like '--') or single quotes. Attackers bypass this using alternative comment syntaxes (/* ... */), inline tautologies (' OR ''='), or double escaping.",
        "best_practice": "Always use database driver parameterized execution: cursor.execute('SELECT ... WHERE col = ?', (val,)). Never interpolate variables with f-strings or format().",
    },
    "CWE-78": {
        "name": "OS Command Injection (CMDi)",
        "category": "Injection / RCE",
        "description": "User-supplied hostname input is passed directly to an operating system shell via subprocess.run(cmd, shell=True).",
        "impact": "Remote Command Execution: allows arbitrary commands to run with the privileges of the web application process, enabling filesystem reads, malware downloads, or server takeover.",
        "canary": "PP_CANARY_CMDI",
        "canary_desc": "A canary token echo payload executed within the system shell context.",
        "exploit_payload": "127.0.0.1; echo PP_CANARY_CMDI",
        "exploit_mechanism": "Shell metacharacters like ';' or '&&' terminate the ping command and execute arbitrary subsequent commands injected by the attacker.",
        "solution_title": "Argument List Execution (shell=False) + Strict Allowlist",
        "solution_mechanism": "Runs the binary directly as an argument list (['ping', flag, '1', host]) without invoking a system shell. Combined with strict alphanumeric/hostname regex validation (^[a-zA-Z0-9.-]+$) to reject invalid input without echoing it.",
        "bad_fix_title": "Incomplete Metacharacter Blacklist",
        "bad_fix_mechanism": "Blocking only ';' or '&&' fails because modern shells offer multiple alternative execution vectors, including command substitution $(cmd), pipes '|', and backticks `cmd`.",
        "best_practice": "Never pass shell=True when executing system commands. Pass arguments as a list of strings and strictly validate inputs against an allowlist.",
    },
    "CWE-22": {
        "name": "Path Traversal (Arbitrary File Read)",
        "category": "File Handling",
        "description": "User-supplied filename parameter is concatenated directly to the public directory path with os.path.join without boundary checks.",
        "impact": "Information Disclosure: allows directory traversal via '../' sequences to read sensitive server files, configuration keys, or application secrets outside the web root.",
        "canary": "PP_CANARY_PATHTRAVERSAL_3d7b",
        "canary_desc": "A secret file located outside the public directory at secrets/secret.txt containing the secret canary string.",
        "exploit_payload": "../../secrets/secret.txt",
        "exploit_mechanism": "Relative path navigation sequences escape the public folder and access files in parent and adjacent secret directories.",
        "solution_title": "Path Normalization & Resolved Root Prefix Check",
        "solution_mechanism": "Uses werkzeug.utils.safe_join to reject directory escape attempts, and verifies that os.path.realpath(filepath) strictly starts with os.path.realpath(PUBLIC_DIR), returning HTTP 403 on boundary violation.",
        "bad_fix_title": "Single-Pass Relative Sequence Stripping",
        "bad_fix_mechanism": "Naive string replacements like filename.replace('../', '') are easily defeated by nested traversal sequences such as '....//', which collapse to '../' after the single replacement.",
        "best_practice": "Use hardened path helpers like safe_join() and always resolve and verify real canonical paths against authorized base directories.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "Network",
        "description": "The application fetches remote resources from user-controlled URLs without validating host addresses.",
        "impact": "Internal Network Scanning: attackers can force the server to connect to internal services, loopback interfaces, or cloud metadata endpoints.",
        "canary": "PP_CANARY_SSRF",
        "canary_desc": "A local canary probe listening on loopback interface.",
        "exploit_payload": "http://127.0.0.1:9999/canary",
        "exploit_mechanism": "Forces server to perform HTTP requests to sensitive internal loopback ports.",
        "solution_title": "Strict URL Scheme & IP Blocklist Validation",
        "solution_mechanism": "Validates protocol to HTTPS only and verifies that resolved IP addresses do not belong to private or loopback subnets.",
        "bad_fix_title": "String Prefix Checking Without DNS Resolution",
        "bad_fix_mechanism": "Matching '127.0.0.1' or 'localhost' is easily bypassed using decimal, hexadecimal (0x7f000001), or IPv6 ([::1]) notations.",
        "best_practice": "Parse URLs, enforce allowed domains, and validate resolved IP addresses against RFC 1918 private ranges.",
    },
}


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

    fixes_dir = templates_dir.parent / "fixes"
    patch_map = {
        "pp-flask-sqli": "01-sqli.patch",
        "pp-flask-cmdi": "02-cmdi.patch",
        "pp-flask-pathtraversal": "03-pathtraversal.patch",
    }

    enriched_evidences = []
    for ev in evidences:
        f = ev.finding
        cwe_info = CWE_EXPLANATIONS.get(f.cwe, {
            "name": f.rule_id,
            "category": "Security",
            "description": f"Potential security vulnerability in {f.file or 'application'}.",
            "impact": "Security risk to the application.",
            "canary": "N/A",
            "canary_desc": "Canary token check",
            "exploit_payload": "N/A",
            "exploit_mechanism": "Exploits unvalidated input.",
            "solution_title": "Input Validation & Hardened Call",
            "solution_mechanism": "Apply input validation and safe APIs.",
            "bad_fix_title": "Incomplete Blacklist",
            "bad_fix_mechanism": "Weak sanitization fails against bypasses.",
            "best_practice": "Follow secure coding guidelines.",
        })

        test_content = ""
        if f.test_path and Path(f.test_path).exists():
            try:
                test_content = Path(f.test_path).read_text(encoding="utf-8")
            except Exception:
                test_content = ""

        diff_patch = ev.diff_patch
        if not diff_patch:
            patch_name = patch_map.get(f.rule_id)
            if patch_name and (fixes_dir / patch_name).exists():
                diff_patch = (fixes_dir / patch_name).read_text(encoding="utf-8")

        enriched_evidences.append({
            "finding": f,
            "diff_patch": diff_patch,
            "suite_passed": ev.suite_passed,
            "cwe_info": cwe_info,
            "test_content": test_content,
            "red_output": f.red.get("output", "") if f.red else "",
            "green_output": f.green.get("output", "") if f.green else "",
        })

    # Summary metrics
    total_findings = len(evidences)
    confirmed_count = sum(1 for e in evidences if e.finding.red and e.finding.red.get("failed"))
    fixed_count = sum(1 for e in evidences if e.finding.status == "fixed")
    mutants_killed = sum(e.finding.mutants_killed[0] for e in evidences if e.finding.mutants_killed)
    total_mutants = sum(e.finding.mutants_killed[1] for e in evidences if e.finding.mutants_killed)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        keep_trailing_newline=True,
    )

    try:
        template = env.get_template("report.html.j2")
    except Exception as exc:
        console.print(f"[yellow]Template load failed: {exc}, using fallback[/yellow]")
        return _generate_basic_html(evidences, output_dir)

    html = template.render(
        evidences=evidences,
        enriched_evidences=enriched_evidences,
        total_findings=total_findings,
        confirmed_count=confirmed_count,
        fixed_count=fixed_count,
        mutants_killed=mutants_killed,
        total_mutants=total_mutants,
    )
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

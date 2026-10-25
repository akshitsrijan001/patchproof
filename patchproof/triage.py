"""Stage 2: Triage findings and build root cause chains."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console

from .models import Finding, TraceStep
from .entrypoint import resolve_entry_point

console = Console(legacy_windows=False)


def build_trace_chain(dataflow_trace: dict[str, Any] | None, file_path: str, line: int, code: str) -> list[TraceStep]:
    """Build source-to-sink trace chain from Semgrep dataflow trace."""
    steps = []

    if dataflow_trace:
        # Parse taint source
        taint_source = dataflow_trace.get("taint_source")
        if taint_source:
            loc = taint_source.get("location", {})
            steps.append(TraceStep(
                file=loc.get("path", file_path),
                line=loc.get("start", {}).get("line", 0),
                code=loc.get("lines", "").strip() if loc.get("lines") else taint_source.get("content", "").strip(),
                role="source",
            ))

        # Parse intermediate vars
        intermediate_vars = dataflow_trace.get("intermediate_vars", [])
        for iv in intermediate_vars:
            loc = iv.get("location", {})
            steps.append(TraceStep(
                file=loc.get("path", file_path),
                line=loc.get("start", {}).get("line", 0),
                code=loc.get("lines", "").strip() if loc.get("lines") else iv.get("content", "").strip(),
                role="propagation",
            ))

        # Parse taint sink
        taint_sink = dataflow_trace.get("taint_sink")
        if taint_sink:
            loc = taint_sink.get("location", {})
            steps.append(TraceStep(
                file=loc.get("path", file_path),
                line=loc.get("start", {}).get("line", 0),
                code=loc.get("lines", "").strip() if loc.get("lines") else taint_sink.get("content", "").strip(),
                role="sink",
            ))

    # Fallback if no dataflow trace
    if not steps:
        steps.append(TraceStep(file=file_path, line=line, code=code, role="sink"))

    return steps


def triage_finding(raw: dict[str, Any], project_root: Path) -> Finding:
    """Convert a raw Semgrep finding into a Finding with root cause analysis."""
    file_path = raw["path"]
    line = raw["start_line"]
    code = raw.get("code", "")
    metadata = raw.get("metadata", {})
    cwe = metadata.get("cwe", "unknown")
    pp_meta = metadata.get("patchproof", {})

    # Build the trace chain
    trace = build_trace_chain(raw.get("dataflow_trace"), file_path, line, code)

    # Find source and sink for display
    source_step = next((s for s in trace if s.role == "source"), None)
    sink_step = next((s for s in trace if s.role == "sink"), trace[-1] if trace else None)

    # Resolve entry point
    abs_file = project_root / file_path
    entry = resolve_entry_point(abs_file, line) if abs_file.exists() else {}

    # Compute stable finding identity
    finding_id = Finding.compute_id(
        rule_id=raw["rule_id"],
        file=file_path,
        enclosing_function=entry.get("function"),
        sink_snippet=sink_step.code if sink_step else code,
    )

    finding = Finding(
        id=finding_id,
        rule_id=raw["rule_id"],
        cwe=cwe,
        severity=raw.get("severity", "ERROR"),
        trace=trace,
        route=entry.get("route"),
        method=entry.get("method", "GET"),
        param=entry.get("param"),
        file=file_path,
        line=line,
        sink_code=sink_step.code if sink_step else code,
        source_code=source_step.code if source_step else None,
        enclosing_function=entry.get("function"),
        status="found",
    )

    console.print(f"  [bold cyan]{finding.rule_id}[/bold cyan] at {file_path}:{line}")
    if finding.route:
        console.print(f"    Route: {finding.method} {finding.route}?{finding.param}=...")
    if source_step and sink_step:
        console.print(f"    Source: {source_step.file}:{source_step.line} → Sink: {sink_step.file}:{sink_step.line}")

    return finding


def triage_all(raw_findings: list[dict[str, Any]], project_root: Path) -> list[Finding]:
    """Triage all raw findings into Finding objects."""
    console.print(f"\n[bold blue]Triaging {len(raw_findings)} finding(s)...[/bold blue]")
    findings = []
    for raw in raw_findings:
        finding = triage_finding(raw, project_root)
        findings.append(finding)
    return findings

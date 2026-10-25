"""Core data models for PatchProof findings and evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class TraceStep:
    """One step in a source-to-sink dataflow trace."""
    file: str
    line: int
    code: str
    role: str  # "source" | "propagation" | "sink"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TraceStep:
        return cls(**d)


@dataclass
class Finding:
    """A single vulnerability finding with full evidence chain."""
    id: str  # hash of rule_id + file + enclosing function + normalized sink snippet
    rule_id: str
    cwe: str
    severity: str
    trace: list[TraceStep]
    route: str | None = None
    method: str | None = None
    param: str | None = None
    file: str | None = None
    line: int | None = None
    sink_code: str | None = None
    source_code: str | None = None
    enclosing_function: str | None = None
    test_path: str | None = None
    red: dict[str, Any] | None = None      # exit code, output, timestamp
    green: dict[str, Any] | None = None
    sarif_before: bool = True
    sarif_after: bool | None = None
    mutants_killed: tuple[int, int] | None = None
    status: str = "found"  # found | confirmed | unconfirmed | fixed | fix_rejected

    @staticmethod
    def compute_id(rule_id: str, file: str, enclosing_function: str | None, sink_snippet: str) -> str:
        """Compute a stable finding identity that ignores line numbers."""
        normalized = re.sub(r'\s+', ' ', sink_snippet.strip())
        raw = f"{rule_id}:{file}:{enclosing_function or ''}:{normalized}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["trace"] = [t.to_dict() if isinstance(t, TraceStep) else t for t in self.trace]
        if self.mutants_killed is not None:
            d["mutants_killed"] = list(self.mutants_killed)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        d = dict(d)
        d["trace"] = [TraceStep.from_dict(t) for t in d.get("trace", [])]
        mk = d.get("mutants_killed")
        if mk is not None:
            d["mutants_killed"] = tuple(mk)
        return cls(**d)

    def save(self, output_dir: Path) -> Path:
        """Save finding to JSON in the output directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"finding-{self.id}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    @classmethod
    def load(cls, path: Path) -> Finding:
        """Load finding from a JSON file."""
        return cls.from_dict(json.loads(path.read_text()))


@dataclass
class Evidence:
    """Collection of evidence for one vulnerability."""
    finding: Finding
    red_output: str = ""
    green_output: str = ""
    diff_patch: str = ""
    scanner_before: dict[str, Any] = field(default_factory=dict)
    scanner_after: dict[str, Any] = field(default_factory=dict)
    suite_passed: bool | None = None
    mutant_results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "red_output": self.red_output,
            "green_output": self.green_output,
            "diff_patch": self.diff_patch,
            "scanner_before": self.scanner_before,
            "scanner_after": self.scanner_after,
            "suite_passed": self.suite_passed,
            "mutant_results": self.mutant_results,
        }

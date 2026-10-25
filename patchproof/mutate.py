"""Sensitivity check: near-miss mutants of fixes."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

from .models import Finding
from .runner import run_test
from .fix import apply_fix_for_finding, revert_fix_for_finding

console = Console(legacy_windows=False)


def get_mutant_patches(fixes_dir: Path, rule_id: str) -> list[Path]:
    """Get near-miss mutant patches for a given rule."""
    mutants_dir = fixes_dir / "mutants"
    if not mutants_dir.exists():
        return []

    # Map rule IDs to mutant file prefix
    prefix_map = {
        "pp-flask-sqli": "sqli",
        "pp-flask-cmdi": "cmdi",
        "pp-flask-pathtraversal": "pathtraversal",
    }

    prefix = prefix_map.get(rule_id, "")
    if not prefix:
        return []

    return sorted(mutants_dir.glob(f"{prefix}-mutant-*.patch"))


def run_sensitivity_check(
    finding: Finding,
    fixes_dir: Path,
    project_root: Path,
) -> tuple[int, int, list[dict[str, Any]]]:
    """Apply near-miss mutants and check if the test catches them.

    Returns: (killed, total, details)
    """
    console.print(f"\n[bold blue]Sensitivity check for {finding.rule_id}...[/bold blue]")

    mutant_patches = get_mutant_patches(fixes_dir, finding.rule_id)
    if not mutant_patches:
        console.print("  [yellow]No mutant patches found[/yellow]")
        return 0, 0, []

    if not finding.test_path:
        console.print("  [yellow]No test to run against mutants[/yellow]")
        return 0, 0, []

    killed = 0
    total = len(mutant_patches)
    details: list[dict[str, Any]] = []

    test_path = Path(finding.test_path)

    # Revert good fix temporarily so mutant patches can apply cleanly on vulnerable code
    reverted_good_fix = False
    if finding.status in ("fixed", "confirmed"):
        reverted_good_fix = revert_fix_for_finding(finding, fixes_dir, project_root)

    try:
        for mutant_patch in mutant_patches:
            console.print(f"\n  Mutant: {mutant_patch.name}")

            # Apply the mutant (weak fix)
            apply_result = subprocess.run(
                ["git", "apply", "--whitespace=fix", str(mutant_patch)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(project_root),
            )

            if apply_result.returncode != 0:
                console.print(f"    [yellow]Could not apply mutant[/yellow]")
                details.append({"mutant": mutant_patch.name, "status": "skipped", "reason": "apply failed"})
                continue

            # Run the test
            result = run_test(test_path, project_root, label=f"mutant {mutant_patch.stem}")

            if result["failed"]:
                # Test catches the weak fix — mutant killed
                console.print(f"    [green]Mutant killed![/green] Test catches weak fix.")
                killed += 1
                details.append({"mutant": mutant_patch.name, "status": "killed"})
            else:
                # Test passes with weak fix — mutant survived
                console.print(f"    [red]Mutant survived![/red] Payload bank may need a bypass.")
                details.append({"mutant": mutant_patch.name, "status": "survived"})

            # Revert the mutant
            subprocess.run(
                ["git", "apply", "--reverse", "--whitespace=fix", str(mutant_patch)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(project_root),
            )
    finally:
        if reverted_good_fix:
            apply_fix_for_finding(finding, fixes_dir, project_root)

    console.print(f"\n  [bold]Sensitivity score: {killed}/{total} mutants killed[/bold]")
    finding.mutants_killed = (killed, total)
    return killed, total, details

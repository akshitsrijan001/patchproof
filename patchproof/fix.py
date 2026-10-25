"""Stage 5: Apply fixes via patch files or autofix."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console(legacy_windows=False)


def apply_patch(
    patch_file: Path,
    project_root: Path,
    reverse: bool = False,
) -> bool:
    """Apply a git patch file."""
    cmd = ["git", "apply", "--whitespace=fix"]
    if reverse:
        cmd.append("--reverse")
    cmd.append(str(patch_file))

    console.print(f"  {'Reverting' if reverse else 'Applying'} patch: {patch_file.name}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(project_root),
    )

    if result.returncode == 0:
        console.print(f"    [green]{'Reverted' if reverse else 'Applied'} successfully[/green]")
        return True
    else:
        # Try with --3way for more flexibility
        cmd_3way = ["git", "apply", "--whitespace=fix", "--3way"]
        if reverse:
            cmd_3way.append("--reverse")
        cmd_3way.append(str(patch_file))
        result2 = subprocess.run(
            cmd_3way,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(project_root),
        )
        if result2.returncode == 0:
            console.print(f"    [green]{'Reverted' if reverse else 'Applied'} with 3-way merge[/green]")
            return True

        console.print(f"    [red]Failed:[/red] {result.stderr.strip()}")
        return False


def apply_fix_for_finding(
    finding: Any,
    fixes_dir: Path,
    project_root: Path,
) -> tuple[bool, str]:
    """Find and apply the appropriate fix for a finding."""
    console.print(f"\n[bold blue]Applying fix for {finding.rule_id}...[/bold blue]")

    # Map rule IDs to patch files
    patch_map = {
        "pp-flask-sqli": "01-sqli.patch",
        "pp-flask-cmdi": "02-cmdi.patch",
        "pp-flask-pathtraversal": "03-pathtraversal.patch",
    }

    patch_name = patch_map.get(finding.rule_id)
    if not patch_name:
        console.print(f"  [yellow]No patch file for {finding.rule_id}[/yellow]")
        return False, ""

    patch_file = fixes_dir / patch_name
    if not patch_file.exists():
        console.print(f"  [yellow]Patch file not found: {patch_file}[/yellow]")
        return False, ""

    # Read diff for evidence
    diff_content = patch_file.read_text(encoding="utf-8")

    success = apply_patch(patch_file, project_root)
    return success, diff_content


def revert_fix_for_finding(
    finding: Any,
    fixes_dir: Path,
    project_root: Path,
) -> bool:
    """Revert the fix for a finding (used for bad-fix demo)."""
    patch_map = {
        "pp-flask-sqli": "01-sqli.patch",
        "pp-flask-cmdi": "02-cmdi.patch",
        "pp-flask-pathtraversal": "03-pathtraversal.patch",
    }

    patch_name = patch_map.get(finding.rule_id)
    if not patch_name:
        return False

    patch_file = fixes_dir / patch_name
    if not patch_file.exists():
        return False

    return apply_patch(patch_file, project_root, reverse=True)

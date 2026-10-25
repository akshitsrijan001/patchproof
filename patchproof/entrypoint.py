"""Resolve Flask route entry points using Python AST."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any


def resolve_entry_point(file_path: Path, target_line: int) -> dict[str, Any]:
    """Use Python AST to find the Flask route, method, and parameter for a given line."""
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, FileNotFoundError, UnicodeDecodeError):
        return {}

    result: dict[str, Any] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if the target line is inside this function
            if node.lineno <= target_line <= (node.end_lineno or node.lineno + 100):
                result["function"] = node.name

                # Look for @app.route or @blueprint.route decorator
                for dec in node.decorator_list:
                    route_info = _parse_route_decorator(dec)
                    if route_info:
                        result.update(route_info)
                        break

                # Search function body for request.args.get / request.form.get
                param = _find_request_param(node, source)
                if param:
                    result["param"] = param

                break

    return result


def _parse_route_decorator(dec: ast.expr) -> dict[str, Any] | None:
    """Extract route path and methods from a @app.route(...) decorator."""
    if isinstance(dec, ast.Call):
        func = dec.func
        # Match app.route(...) or blueprint.route(...)
        if isinstance(func, ast.Attribute) and func.attr == "route":
            info: dict[str, Any] = {}
            # First positional arg is the route path
            if dec.args and isinstance(dec.args[0], ast.Constant):
                info["route"] = dec.args[0].value

            # Look for methods keyword
            info["method"] = "GET"
            for kw in dec.keywords:
                if kw.arg == "methods":
                    if isinstance(kw.value, ast.List):
                        methods = []
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant):
                                methods.append(elt.value)
                        if methods:
                            info["method"] = methods[0]

            return info if "route" in info else None
    return None


def _find_request_param(func_node: ast.FunctionDef | ast.AsyncFunctionDef, source: str) -> str | None:
    """Find request.args.get('param') or request.form.get('param') in a function body."""
    # First try AST traversal
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "get":
                val = func.value
                if isinstance(val, ast.Attribute) and val.attr in ("args", "form"):
                    if isinstance(val.value, ast.Name) and val.value.id == "request":
                        if node.args and isinstance(node.args[0], ast.Constant):
                            return str(node.args[0].value)
        elif isinstance(node, ast.Subscript):
            val = node.value
            if isinstance(val, ast.Attribute) and val.attr in ("args", "form"):
                if isinstance(val.value, ast.Name) and val.value.id == "request":
                    if isinstance(node.slice, ast.Constant):
                        return str(node.slice.value)

    # Fallback to regex
    func_source = ast.get_source_segment(source, func_node)
    if not func_source:
        lines = source.splitlines()
        start = func_node.lineno - 1
        end = func_node.end_lineno or start + 50
        func_source = "\n".join(lines[start:end])

    patterns = [
        r'request\.args\.get\(\s*["\'](\w+)["\']',
        r'request\.form\.get\(\s*["\'](\w+)["\']',
        r'request\.args\[\s*["\'](\w+)["\']',
        r'request\.form\[\s*["\'](\w+)["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, func_source)
        if match:
            return match.group(1)

    return None

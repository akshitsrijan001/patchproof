"""Unit tests for entry point resolution."""

import tempfile
from pathlib import Path

from patchproof.entrypoint import resolve_entry_point


SAMPLE_APP = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return q

@app.route("/submit", methods=["POST"])
def submit():
    data = request.form.get("data")
    return data
'''


def test_resolve_route():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(SAMPLE_APP)
        f.flush()
        path = Path(f.name)

    result = resolve_entry_point(path, 7)  # Line inside search()
    assert result.get("route") == "/search"
    assert result.get("function") == "search"
    assert result.get("param") == "q"
    path.unlink()


def test_resolve_post_route():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(SAMPLE_APP)
        f.flush()
        path = Path(f.name)

    result = resolve_entry_point(path, 12)  # Line inside submit()
    assert result.get("route") == "/submit"
    assert result.get("method") == "POST"
    assert result.get("param") == "data"
    path.unlink()


def test_nonexistent_file():
    result = resolve_entry_point(Path("/nonexistent.py"), 1)
    assert result == {}

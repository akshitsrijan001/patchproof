"""Test cases for pp-flask-pathtraversal rule."""

import os
from flask import request, send_file
from werkzeug.utils import safe_join

PUBLIC_DIR = "/app/public"

# --- Vulnerable patterns ---

def vuln_open():
    filename = request.args.get("file")
    filepath = os.path.join(PUBLIC_DIR, filename)
    # ruleid: pp-flask-pathtraversal
    return open(filepath, "r").read()

def vuln_send_file():
    filename = request.args.get("file")
    filepath = os.path.join(PUBLIC_DIR, filename)
    # ruleid: pp-flask-pathtraversal
    return send_file(filepath)

# --- Fixed patterns ---

# ok: pp-flask-pathtraversal
def fixed_safe_join():
    filename = request.args.get("file")
    filepath = safe_join(PUBLIC_DIR, filename)
    return send_file(filepath)

# ok: pp-flask-pathtraversal
def fixed_werkzeug_safe_join():
    from werkzeug.utils import safe_join
    filename = request.args.get("file")
    filepath = safe_join(PUBLIC_DIR, filename)
    return open(filepath, "r").read()

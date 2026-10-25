"""Deliberately vulnerable Flask app with SQL injection, command injection, and path traversal."""

import os
import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

# --- Database setup ---
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
PUBLIC_DIR = os.path.join(os.path.dirname(__file__), "public")
SECRET_DIR = os.path.join(os.path.dirname(__file__), "secrets")


def init_db():
    """Initialize the database with test data including a canary row."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'alice', 'user')")
    c.execute("INSERT INTO users VALUES (2, 'bob', 'user')")
    # Canary row — this should never be returned by a legitimate search
    c.execute("INSERT INTO users VALUES (99, 'PP_CANARY_SQLI_8f2a', 'canary')")
    conn.commit()
    conn.close()


def init_files():
    """Create public files and canary secret file."""
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    os.makedirs(SECRET_DIR, exist_ok=True)

    # Public file
    with open(os.path.join(PUBLIC_DIR, "readme.txt"), "w") as f:
        f.write("This is a public file.\n")

    # Canary secret file — should never be accessible via /download
    with open(os.path.join(SECRET_DIR, "secret.txt"), "w") as f:
        f.write("PP_CANARY_PATHTRAVERSAL_3d7b\n")


# Initialize on import
init_db()
init_files()


@app.route("/")
def index():
    """Home page."""
    return jsonify({
        "app": "PatchProof Vulnerable Demo App",
        "routes": ["/search?q=", "/ping?host=", "/download?file="],
    })


# --- Vulnerability 1: SQL Injection (CWE-89) ---
@app.route("/search")
def search():
    """Search users by name. VULNERABLE: SQL injection via f-string."""
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # VULNERABLE: user input directly in query string
    query = f"SELECT name, role FROM users WHERE name LIKE '%{q}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify({"query": q, "results": [{"name": r[0], "role": r[1]} for r in results]})


# --- Vulnerability 2: OS Command Injection (CWE-78) ---
@app.route("/ping")
def ping():
    """Ping a host. VULNERABLE: command injection via shell=True."""
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: user input in shell command
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return jsonify({
        "host": host,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    })


# --- Vulnerability 3: Path Traversal (CWE-22) ---
@app.route("/download")
def download():
    """Download a file. VULNERABLE: path traversal via user input."""
    filename = request.args.get("file", "readme.txt")
    # VULNERABLE: user input joined into path without sanitization
    filepath = os.path.join(PUBLIC_DIR, filename)
    try:
        return send_file(filepath)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


if __name__ == "__main__":
    app.run(debug=True, port=5001)

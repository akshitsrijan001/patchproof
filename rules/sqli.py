"""Test cases for pp-flask-sqli rule."""

import sqlite3
from flask import request

# --- Vulnerable patterns (should trigger the rule) ---

def vuln_fstring(db):
    q = request.args.get("q")
    query = f"SELECT name FROM users WHERE name = '{q}'"
    # ruleid: pp-flask-sqli
    db.execute(query)

def vuln_format(db):
    q = request.args.get("q")
    # ruleid: pp-flask-sqli
    db.execute("SELECT name FROM users WHERE name = '%s'" % q)

def vuln_concat(db):
    q = request.args.get("q")
    # ruleid: pp-flask-sqli
    db.execute("SELECT name FROM users WHERE name = '" + q + "'")

# --- Fixed patterns (should NOT trigger the rule) ---

# ok: pp-flask-sqli
def fixed_parameterized(db):
    q = request.args.get("q")
    db.execute("SELECT name FROM users WHERE name = ?", (q,))

# ok: pp-flask-sqli
def fixed_parameterized_named(db):
    q = request.args.get("q")
    db.execute("SELECT name FROM users WHERE name = :name", {"name": q})

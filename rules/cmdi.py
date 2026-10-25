"""Test cases for pp-flask-cmdi rule."""

import os
import subprocess
from flask import request

# --- Vulnerable patterns ---

# ruleid: pp-flask-cmdi
def vuln_subprocess_shell(host=None):
    host = request.args.get("host")
    cmd = f"ping -c 1 {host}"
    subprocess.run(cmd, shell=True, capture_output=True)

# ruleid: pp-flask-cmdi
def vuln_os_system():
    host = request.args.get("host")
    os.system(f"ping -c 1 {host}")

# ruleid: pp-flask-cmdi
def vuln_os_popen():
    host = request.args.get("host")
    os.popen(f"ping -c 1 {host}")

# --- Fixed patterns ---

# ok: pp-flask-cmdi
def fixed_arg_list():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], capture_output=True)

# ok: pp-flask-cmdi
def fixed_no_shell():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)

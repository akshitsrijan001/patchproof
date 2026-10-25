"""Test cases for pp-flask-cmdi rule."""

import os
import subprocess
from flask import request

# --- Vulnerable patterns ---

def vuln_subprocess_shell(host=None):
    host = request.args.get("host")
    cmd = f"ping -c 1 {host}"
    # ruleid: pp-flask-cmdi
    subprocess.run(cmd, shell=True, capture_output=True)

def vuln_os_system():
    host = request.args.get("host")
    # ruleid: pp-flask-cmdi
    os.system(f"ping -c 1 {host}")

def vuln_os_popen():
    host = request.args.get("host")
    # ruleid: pp-flask-cmdi
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

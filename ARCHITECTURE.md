# PatchProof: Security Rules That Generate Regression Tests

Problem 19. Starting point: Semgrep.

Tagline: **A scanner tells you something looks wrong. PatchProof proves it is wrong, proves the fix works, and makes sure it never comes back.**

---

## 1. The idea in one paragraph

Semgrep finds a vulnerability. Normally a developer reads it, guesses if it is real, patches it, and moves on with nothing to stop it coming back. PatchProof closes that loop automatically. For every finding it (1) traces the root cause from source to sink with file and line links, (2) generates an exploit-style pytest regression test, (3) runs the test on the vulnerable code and shows it FAIL (this is proof the bug is real), (4) applies the fix, (5) runs the test again and shows it PASS, (6) re-scans with Semgrep to show the finding is gone, and (7) produces one evidence report per vulnerability.

Red then green, backed by a scanner diff. That is the whole product.

---

## 2. What makes this a winning project

**Proof, not alerts.** Every confirmed finding comes with a failing exploit test, and a failing test is proof of exploitability. The reverse does not hold: a test that passes on vulnerable code does not prove a false positive, because the payload bank or canary may simply have missed. Those findings are marked `unconfirmed` and reported with the reason, never silently dismissed. We only claim what we can prove.

**Canary-based oracles.** The target app is seeded with secret canary values (a fake secret file, a secret DB row, a nonce file). A test passes or fails based on whether the canary leaks. This makes the evidence easy to see and hard to argue with.

**Bypass-resistant tests.** Each test runs a payload bank, not one payload. A weak fix (like a blacklist filter) fails against a bypass payload. We demo this on purpose with a "bad fix" to show the test is not trivial.

**Test quality check.** We apply near-miss mutants of the fix (weak or partial fixes that still leave the bug exploitable, such as a blacklist filter or a check on the unresolved path) and confirm the generated test still fails on each. Mutants are never just the original vulnerable code, because the red run already proved the test catches that. This is mutation testing applied to security tests, and the bad-fix demo is its headline instance.

**Rules ship with their own tests.** Each custom Semgrep rule carries metadata that links it to a test template, so adding a new rule automatically adds a new regression test type. Each rule also ships with a `semgrep --test` file proving it fires on the vulnerable shape and stays silent on the fixed shape.

**CI-native.** A GitHub Action runs the whole pipeline on a pull request and comments the verification report. The generated tests are committed to the repo so the bug stays dead: a later PR that reintroduces a fixed bug turns CI red and names the exact regression test.

**One-command demo.** `patchproof demo` runs the full story on three vulnerabilities in under two minutes.

---

## 3. The three demo vulnerabilities

All three live in a small deliberately vulnerable Flask app (`target/vuln_app`).

**Vulnerability 1: SQL injection (CWE-89).** Route `/search?q=` builds a query with an f-string. Canary: a secret row in the `users` table. Exploit: `' OR '1'='1' --` returns the secret row. Fix: parameterized query.

**Vulnerability 2: OS command injection (CWE-78).** Route `/ping?host=` calls `subprocess.run(f"ping {host}", shell=True)`. Canary: a nonce file. Exploit: `127.0.0.1; touch /tmp/pp_<nonce>` creates the file. Fix: argument list with `shell=False` plus input validation.

**Vulnerability 3: Path traversal (CWE-22).** Route `/download?file=` joins user input into a path. Canary: `secret.txt` outside the public folder. Exploit: `../../secret.txt` returns the canary string. Fix: `safe_join` plus resolved-path prefix check.

**Stretch vulnerability 4 (only if time allows): SSRF (CWE-918).** Route `/fetch?url=` requests any URL. Exploit hits a local canary server. Fix: scheme and host allowlist.

Do not start the stretch until the three core ones have full evidence reports.

---

## 4. System architecture

```
          +-----------+     +-----------+     +--------------+
 repo --> | 1. SCAN   | --> | 2. TRIAGE | --> | 3. GENERATE  |
          | semgrep   |     | root cause|     | pytest tests |
          +-----------+     +-----------+     +--------------+
                                                     |
          +-----------+     +-----------+     +--------------+
          | 7. REPORT | <-- | 6. VERIFY | <-- | 4. RED RUN   |
          | html + md |     | rescan +  |     | must FAIL    |
          +-----------+     | green run |     +--------------+
                ^           +-----------+            |
                |                 ^            +--------------+
                |                 +----------- | 5. FIX       |
                |                              | patch + apply|
                +--- evidence store (JSON) --- +--------------+
```

Every stage reads and writes one shared object, the `Finding` record, stored as JSON in `.patchproof/`. This keeps stages independent, testable, and resumable.

### Stage 1: Scan

Run Semgrep with the custom PatchProof ruleset only. Public rulepacks add noise and unstable finding counts; they can be enabled with a flag but are off for the demo.

```
semgrep scan --config rules/ --dataflow-traces --json-output=.patchproof/before.json --sarif-output=.patchproof/before.sarif .
```

The engine can be Semgrep Community Edition or Opengrep (the LGPL-2.1 fork, rule- and output-compatible). PatchProof does not depend on any feature that differs between them; in particular it computes its own finding identity instead of relying on Semgrep fingerprints (see Stage 6). Save the raw JSON and the SARIF file as evidence.

Rules use taint mode so Semgrep returns source-to-sink dataflow traces. The key design rule: **sinks model the unsafe shape, not the dangerous function.** A sink is only the specific argument that makes the call dangerous (the query string of `execute`, the command of `subprocess.run(..., shell=True)`, the path given to `open` or `send_file`), selected with `focus-metavariable`. The correct fix then stops matching for the right reason. In a parameterized query the user input still reaches `execute`, but only as a bound parameter, never inside the query string, so there is no finding. Sanitizers are not used to represent "the safe form of the call"; a taint sanitizer only fits a function that transforms the value itself (for example `safe_join`). Full rules are in section 8.

Gate for every rule: it must fire on the vulnerable code and stay silent on the fixed code, checked with `semgrep --test`. Verify this in the first hours, because the Stage 6 scanner diff depends on it.

### Stage 2: Triage and root cause

Parse the Semgrep JSON into `Finding` objects. For taint findings, read the dataflow trace and build the chain: source (where user input enters), intermediate steps, sink (dangerous call). For each step store file, line, column and the code snippet.

Then resolve the **entry point** with Python's `ast` module: find the enclosing function of the sink, read its `@app.route` decorator for the URL path and method, and read the source expression (like `request.args.get("q")`) for the parameter name. This is what lets us generate a real HTTP test instead of a generic one.

Output: a root cause card with clickable `file:line` links (GitHub permalinks when a commit SHA is known).

### Stage 3: Test generation

Hybrid approach, deterministic first:

1. **Template engine (primary).** One Jinja2 template per CWE class (`sqli`, `cmdi`, `pathtraversal`, `ssrf`). The template is filled with route, method, parameter, payload bank and canary check from the Finding.
2. **LLM adapter (optional, behind a flag).** If the entry point cannot be resolved (non-Flask code, custom routing), call the Claude API to adapt the template. The output is never trusted: it must pass the red-run check in stage 4 or it is discarded and regenerated up to 3 times.

Why this split: templates make the demo reliable and fast, the LLM shows range, and the red-run gate keeps the LLM honest.

### Stage 4: Red run (proof of exploitability)

Run the generated test against the vulnerable code inside the PatchProof Docker container, always, not only when Docker happens to be available (see section 13). The test must FAIL, and the failure must be the right kind (assertion on the canary, not an import error or timeout). Capture pytest output as evidence and mark the finding `confirmed`.

If the test passes on vulnerable code, mark the finding **unconfirmed: exploitability not demonstrated**. This means the tool could not prove it, not that the finding is false. It may be a false positive, or the payload bank or entry point resolution may have missed. Unconfirmed findings are listed in the report with the reason and are not fixed automatically.

### Stage 5: Fix

Two fix sources:

1. **Semgrep autofix.** Rules include a `fix:` key for simple cases.
2. **Curated patch files.** For the demo vulnerabilities, ship reviewed `.patch` files in `fixes/`. Applied with `git apply`.

Fixes must make the rule stop matching for the real reason, not by hiding the pattern. In particular the path traversal fix must route the path through `werkzeug.utils.safe_join` (a value-transforming sanitizer Semgrep understands) in addition to the resolved-path prefix check, because Semgrep taint analysis does not treat an `if` guard as sanitization. Without `safe_join` the fix is correct but the rescan still reports it.

Optional: LLM-suggested patch shown as a proposal only, never auto-applied without the red/green verification.

### Stage 6: Verify

Three checks after the patch is applied:

1. The generated regression test now PASSES (green run).
2. Semgrep rescan no longer reports the finding. Compare `before.json` and `after.json` using PatchProof's own finding identity: a hash of rule id, file, enclosing function and the normalized sink snippet. Line numbers are deliberately excluded, because a patch shifts lines and would make unrelated findings look new. Semgrep's own fingerprints are not used, since stable fingerprinting is not part of Semgrep Community Edition.
3. The existing test suite still passes (no regression from the fix).

Then the **sensitivity check**: apply near-miss mutants of the fix and confirm the test fails on each. Mutants are weak or partial fixes that remain exploitable, never the original vulnerable code (the red run already covers that). Examples: for SQLi, manually escaping single quotes instead of parameterizing; for command injection, a blacklist that strips `;` but allows `$(...)` and `|`; for path traversal, stripping `../` once (bypassed by `....//`) or checking the prefix on the unresolved path. Report the score, like 3 of 3 mutants killed. A surviving mutant means the payload bank needs a new bypass payload, which is itself a useful finding.

### Stage 7: Report

One report per vulnerability, plus a summary page. Format: Markdown and a single static HTML file. Contents listed in section 7.

---

## 5. Repository layout

```
patchproof/
├── ARCHITECTURE.md
├── README.md
├── pyproject.toml
├── patchproof/
│   ├── cli.py                # Typer CLI: scan, gen, verify, report, demo
│   ├── models.py             # Finding, TraceStep, Evidence (dataclasses)
│   ├── scan.py               # runs semgrep, parses json/sarif
│   ├── triage.py             # dataflow trace -> root cause chain
│   ├── entrypoint.py         # ast: find route, param, method
│   ├── generate.py           # jinja2 render + optional LLM adapter
│   ├── runner.py             # runs pytest, captures output, red/green logic
│   ├── fix.py                # apply autofix or patch files
│   ├── verify.py             # sarif diff, full-suite check
│   ├── mutate.py             # sensitivity check (near-miss mutants)
│   └── report.py             # md + html report builder
├── rules/
│   ├── sqli.yml
│   ├── sqli.py               # rule test cases (# ruleid: / # ok:) for semgrep --test
│   ├── cmdi.yml
│   ├── cmdi.py
│   ├── pathtraversal.yml
│   ├── pathtraversal.py
│   └── ssrf.yml              # stretch
├── templates/
│   ├── test_sqli.py.j2
│   ├── test_cmdi.py.j2
│   ├── test_pathtraversal.py.j2
│   └── report.html.j2
├── payloads/
│   └── payloads.yml          # payload banks per CWE, incl. bypass variants
├── target/
│   └── vuln_app/             # deliberately vulnerable Flask app + canaries
├── fixes/
│   ├── 01-sqli.patch
│   ├── 02-cmdi.patch
│   ├── 03-pathtraversal.patch
│   ├── bad-fix-cmdi.patch    # weak fix for the bypass demo
│   └── mutants/              # near-miss weak fixes per vulnerability
├── generated_tests/          # output, committed to the repo
├── reports/                  # output
├── tests/                    # unit tests for PatchProof itself
├── .github/workflows/patchproof.yml
└── Dockerfile
```

---

## 6. Key data model

```python
@dataclass
class TraceStep:
    file: str
    line: int
    code: str
    role: str            # "source" | "propagation" | "sink"

@dataclass
class Finding:
    id: str              # hash of rule_id + file + enclosing function + normalized sink snippet (no line numbers)
    rule_id: str
    cwe: str
    severity: str
    trace: list[TraceStep]
    route: str | None
    method: str | None
    param: str | None
    test_path: str | None = None
    red: dict | None = None      # exit code, output, timestamp
    green: dict | None = None
    sarif_before: bool = True
    sarif_after: bool | None = None
    mutants_killed: tuple[int, int] | None = None
    status: str = "found"        # found | confirmed | unconfirmed | fixed | fix_rejected
```

---

## 7. What each evidence report contains

For every vulnerability, in this order:

1. **Summary:** title, CWE, severity, final status (FIXED AND VERIFIED, FIX REJECTED, or UNCONFIRMED).
2. **Root cause:** source to sink chain with `file:line` links and code snippets.
3. **Why it is exploitable:** one short paragraph plus the exact payload.
4. **Generated test:** the full pytest file.
5. **Red run:** pytest output showing the failure on vulnerable code, with the canary leak visible.
6. **Fix:** the unified diff.
7. **Green run:** pytest output showing the pass after the fix.
8. **Scanner diff:** Semgrep finding before, gone after, matched by PatchProof finding identity (raw JSON and SARIF attached).
9. **Suite check:** existing tests still pass.
10. **Sensitivity score:** mutants killed out of total.
11. **Reproduce it yourself:** three copy-paste commands.

The summary page lists all vulnerabilities with a green/red badge and a timeline strip: scan, red, fix, green, rescan.

---

## 8. Example artifacts

### Rules (taint mode, unsafe-shape sinks, with test metadata)

```yaml
rules:
  - id: pp-flask-sqli
    mode: taint
    languages: [python]
    severity: ERROR
    message: User input flows into the text of a SQL query.
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      # Only the query string is a sink. Bound parameters are not.
      - patterns:
          - pattern: $DB.execute($QUERY, ...)
          - focus-metavariable: $QUERY
    metadata:
      cwe: CWE-89
      patchproof:
        template: sqli
        payloads: sqli

  - id: pp-flask-cmdi
    mode: taint
    languages: [python]
    severity: ERROR
    message: User input flows into a shell command string.
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      # Only a command run through a shell is a sink. An argument list with shell=False is not.
      - patterns:
          - pattern-either:
              - pattern: subprocess.$FUNC($CMD, ..., shell=True, ...)
              - pattern: os.system($CMD)
              - pattern: os.popen($CMD, ...)
          - focus-metavariable: $CMD
    metadata:
      cwe: CWE-78
      patchproof:
        template: cmdi
        payloads: cmdi

  - id: pp-flask-pathtraversal
    mode: taint
    languages: [python]
    severity: ERROR
    message: User input flows into a filesystem path.
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: open($PATH, ...)
              - pattern: send_file($PATH, ...)
          - focus-metavariable: $PATH
    pattern-sanitizers:
      # A real sanitizer: safe_join transforms the value and returns None on traversal.
      - pattern: werkzeug.utils.safe_join(...)
      - pattern: safe_join(...)
    metadata:
      cwe: CWE-22
      patchproof:
        template: pathtraversal
        payloads: pathtraversal
```

What this buys: `db.execute(f"SELECT name FROM users WHERE name = '{q}'")` and the two-step `query = f"..."; db.execute(query)` both produce a finding, while the fixed `db.execute("SELECT name FROM users WHERE name = ?", (q,))` does not, because `$QUERY` is a constant string. The same logic applies to `subprocess.run(["ping", "-c", "1", host])` with `shell=False`. Each rule has a matching `rules/<name>.py` file with `# ruleid:` and `# ok:` cases covering exactly these vulnerable and fixed shapes.

### Generated test (output of the sqli template)

```python
import pytest
from target.vuln_app.app import app

PAYLOADS = ["' OR '1'='1' --", "x' UNION SELECT secret FROM users --"]
CANARY = "PP_CANARY_SQLI_8f2a"

@pytest.fixture
def client():
    return app.test_client()

@pytest.mark.parametrize("payload", PAYLOADS)
def test_search_does_not_leak_secret_row(client, payload):
    r = client.get("/search", query_string={"q": payload})
    assert CANARY not in r.get_data(as_text=True)
```

Linked root cause comment at the top of every generated test:

```python
# PatchProof | rule pp-flask-sqli | CWE-89
# source: app.py:14  request.args.get("q")
# sink:   app.py:18  db.execute(f"SELECT ... {q}")
```

---

## 9. Extra features (pick in this order)

**Core (must ship):** the 7-stage pipeline, three vulnerabilities, per-vulnerability reports, one-command demo, and hand-written rule tests (`# ruleid:` / `# ok:` annotations, run with `semgrep --test`) proving each rule fires on vulnerable code and stays silent on fixed code.

**Big wins (ship if core is done by hour 24 of 36):**

1. **Bad fix demo.** Apply `bad-fix-cmdi.patch` (a blacklist that blocks `;` only). The test with the bypass payload `$(touch ...)` still FAILS. Report says "fix rejected: bypass found". This is the most memorable moment of the demo.
2. **Sensitivity score** from near-miss mutants (see Stage 6). Skip it rather than ship trivial mutants that just restore the original bug.
3. **GitHub Action** that comments the report summary on a PR.
4. **Unconfirmed finding handling** so findings the tool cannot prove are reported separately, with the reason, instead of being fixed blindly or dismissed.
5. **Reintroduction demo.** A PR that brings back a fixed bug; the committed regression test turns CI red and names the test. Almost free once the GitHub Action works, and the clearest proof of the core thesis.

**Nice to have:**

6. Self-contained HTML report with a collapsible timeline and syntax highlighting.
7. Report integrity hash (SHA-256 of all evidence files) so the report is tamper-evident.
8. Streamlit page to browse findings live during the demo.
9. SSRF as the fourth vulnerability.

Do not build all of these. A polished core beats a wide unfinished project.

---

## 10. Build plan (36-hour version)

The build is a vertical slice first, then breadth. SQLi goes through all seven stages before work starts on the other two vulnerabilities. A pipeline that works end to end on one vulnerability is demoable; three pipelines that each stop at stage 3 are not.

**Hours 0-3: Setup and rule spike.** Repo, `pyproject.toml`, Typer skeleton, Dockerfile, and pre-build the image on the demo machine. Write the vulnerable Flask app with all three vulnerabilities and canaries, plus a fixed version of each. Write the three rules and their `# ruleid:` / `# ok:` test files. Gate: `semgrep --test` passes, meaning every rule fires on vulnerable code and is silent on fixed code. If a rule cannot be made to clear on the fixed code, fix the rule now, not at hour 20.

**Hours 3-11: SQLi vertical slice.** Scan, parse into `Finding`, trace chain, `ast` entry point, sqli template, red run, apply patch, green run, rescan diff, plain Markdown report. Ugly is fine. Gate (hour 11): `patchproof demo --only sqli` shows red, fix, green, clean rescan and a report.

**Hours 11-18: Breadth.** Command injection and path traversal templates, payload banks and patches. The pipeline already exists, so this is mostly templates and payloads. Gate (hour 18): all three vulnerabilities go red then green with clean rescans.

**Hours 18-24: Evidence quality.** Full-suite check, finding identity hardening, unconfirmed handling, complete per-vulnerability reports, summary page, `patchproof demo` for all three. Gate (hour 24): core is done. This is the checkpoint that unlocks section 9.

**Hours 24-30: Big wins.** Bad-fix demo first, then the GitHub Action with the reintroduction PR, then near-miss mutants.

**Hours 30-34: Polish.** HTML report, README, record the backup video, rehearse the demo on the actual demo machine with Docker running. Freeze code at hour 34.

**Hours 34-36: Buffer.** Rehearsal only. No new code.

If the hackathon is 24 hours: setup and rule spike 0-2, SQLi slice 2-8, breadth 8-13, evidence quality 13-18, bad-fix demo 18-20, polish and video 20-23, freeze at 23.

### Suggested team split (three people)

The split follows the slice, not the stages, so nobody waits on an upstream stage that does not exist yet.

**Person A (pipeline owner):** builds the SQLi vertical slice end to end (models, scan, triage, entry point, runner, fix, verify) and owns the pipeline code afterwards.
**Person B (vulnerabilities owner):** target app, canaries, fixed versions, rules and rule tests in hours 0-3; then the cmdi and path traversal templates, payload banks, patches and near-miss mutants.
**Person C (evidence and delivery owner):** Docker image; the report builder, started at hour 3 against a hand-written sample `Finding` JSON so it does not wait on Person A; summary page, GitHub Action, demo command, README and video.

All three meet at each gate. If a gate is missed, the next phase starts with whatever passed, and section 9 shrinks first.

---

## 11. Tech stack

Python 3.11, Semgrep Community Edition CLI (or Opengrep, interchangeable), pytest, Flask (target only), Jinja2, Typer and Rich for the CLI, GitPython or plain `git` calls, Docker for isolated runs, GitHub Actions. Optional: Claude API for the LLM adapter, Streamlit for a live dashboard.

---

## 12. Safety and honesty notes

Exploit payloads only run against the bundled local target app, inside a subprocess or container, never against anything external. Canary files are fake. The tool is a verification aid for code the user owns.

Be upfront in the pitch about the limit: template-based tests cover known vulnerability classes where the entry point is resolvable. The LLM adapter extends this, but every generated test must still pass the red-run gate. The same honesty applies to triage: a failing test proves exploitability, but a passing test on vulnerable code proves nothing, which is why such findings are reported as unconfirmed rather than as false positives.

---

## 13. Risks and fixes

**Rule still fires after the fix.** The most likely silent failure, and it kills the before/after scanner evidence. The cause is almost always a sink that models the whole function instead of the dangerous argument, or a fix that relies on an `if` guard Semgrep cannot see. Prevention: `focus-metavariable` sinks, value-transforming sanitizers only, and the `semgrep --test` gate in hours 0-3.

**Finding identity unstable across scans.** Line numbers shift after a patch, and Semgrep CE does not provide stable fingerprints. Use PatchProof's own identity hash (Stage 6) and unit-test it by inserting blank lines above a finding and checking the identity does not change.

**Semgrep trace missing for some rules.** Fall back to pattern match location and use `ast` to infer the source. Keep rules in taint mode for the demo.

**Flaky tests (ports, temp files).** Use Flask's `test_client` instead of a real server and use `tmp_path` for nonces.

**Cross-platform compatibility (Windows & Linux).** The pipeline has been engineered with full native Windows & POSIX cross-platform support:
- Native virtual environment binary resolution (`find_semgrep()` and `sys.executable`) to avoid PATH reliance.
- Multi-platform command execution handling (e.g., OS-adaptive ping flags `-n 1` on Windows, `-c 1` on POSIX).
- Full UTF-8 subprocess stream decoding and console renderer fallback to prevent legacy Windows console `charmap` encode/decode errors.
- Clean mutant patch isolation: the mutation testing engine automatically reverts good fixes temporarily during sensitivity analysis, applies near-miss mutants against the unpatched baseline, and restores verified fixes after score calculation.
- Docker containerization remains available via `Dockerfile` for standardized headless CI/CD execution.

**Live demo failure.** Always have the pre-recorded video and pre-generated reports ready.

**Scope creep.** Features from section 9 are gated by the hour-24 checkpoint.

---

## 14. Demo script (4 minutes)

1. **0:00** Problem: scanners give alerts, not proof. One sentence.
2. **0:20** Run `patchproof demo`. Show Semgrep finding three vulnerabilities.
3. **0:50** Open vulnerability 1 (SQLi). Show root cause chain, generated test, red run leaking the canary.
4. **1:30** Apply the fix. Show green run and the clean rescan.
5. **2:00** Vulnerability 2 (command injection) with the **bad fix**: show the test still failing on the bypass payload. Then apply the real fix, green.
6. **3:00** Vulnerability 3 (path traversal) quickly, then the summary page with sensitivity scores.
7. **3:30** Show the GitHub Action comment on a PR, then the reintroduction PR: a fixed bug comes back and CI goes red, naming the regression test. Close with the tagline.

---

## 15. Judging checklist

- Three separate vulnerabilities, each with a full evidence report.
- Test fails before the fix and passes after, shown on screen.
- Root cause links to exact source lines.
- Semgrep before/after proof.
- Every rule proven to fire on vulnerable code and stay silent on fixed code (`semgrep --test`).
- Unconfirmed findings reported honestly, not hidden or called false positives.
- A fix that gets rejected (the bad fix moment).
- Reproducible with one command.
- Clean README, architecture doc, and a backup video.

---
name: dbugs triage
description: This skill should be used when the user runs "/dbugs:triage", or asks to "triage this CVE", "triage PT-2026-…", "assess/prioritize this vulnerability", "how urgent is CVE-…", "should we patch this now". Produces a structured triage verdict for a single vulnerability id by gathering its dbugs detail, references, trending/social signal, and related news, then recommending an action.
argument-hint: <cve-or-pt-id>
allowed-tools: Bash, Read
version: 0.1.0
---

# dbugs triage

## Purpose

Turn a single vulnerability id into an actionable triage verdict: how severe
it is, whether it is exploitable, whether a fix exists, how much attention it
is drawing, and what to do about it. Drive the read-only `dbugs` CLI to gather
the evidence, then synthesize — do not rely on prior knowledge of the CVE.

This skill builds on the `query` skill; consult
`../query/references/commands.md` for any flag details.

## Input

The argument is one vulnerability id — a PT id (`PT-2026-61063`) or a CVE id
(`CVE-2026-63030`). If none was provided, ask for one. If the argument is not
id-shaped, ask the user to confirm the id rather than guessing.

## Prerequisite check

Confirm the CLI is available once before gathering:

```bash
dbugs --help >/dev/null 2>&1 && echo OK || echo MISSING
```

If missing, direct the user to install `dbugs` (see the `query` skill). If the
project uses a virtualenv, use `.venv/bin/dbugs`.

## Gather (run these, tolerate failures)

Run the commands below. Each is independent; if one fails or returns nothing,
note it and continue — a triage with partial evidence is still useful.

1. **Core detail** (always):
   ```bash
   dbugs --json vuln <id>
   ```
   Extract `max_score`, `max_severity`, `has_exploits`, `has_fix`, `created`,
   `updated`, `vendors`, `products`, `cwe_ids`, `cvss`, and `references`.

2. **Exploit references** (to see *what* exploits exist):
   ```bash
   dbugs vuln <id> --source Exploit
   ```
   Note reference URLs, and GitHub `stars`/`forks` if present (a popular PoC
   raises urgency).

3. **Trending / social pressure** (may 404 if not trending — that is fine):
   ```bash
   dbugs --json trend <id>
   ```
   A high post count means active chatter, which raises urgency.

4. **Related news** (only when the id is a CVE):
   ```bash
   dbugs news --cve <id> --limit 5
   ```

## Verdict format

Produce a compact report:

- **Header** — `<id>` (+ CVE/PT cross-id), affected `vendor/product`.
- **Severity** — `max_severity` + CVSS `max_score` (and vector from `cvss` if
  present).
- **Exploitability** — `has_exploits`; if true, list the exploit references
  (URL, source, stars/forks). If false, state "no known public exploit in
  dbugs".
- **Fix status** — `has_fix`; point at any `Vendor Advisory` reference.
- **Attention** — trend post count if trending; related news headlines if any.
- **Recommendation** — a one-line prioritized action, using this rubric:
  - **Patch now** — CRITICAL/HIGH *and* `has_exploits` (especially if
    trending or a popular PoC exists).
  - **Patch soon** — CRITICAL/HIGH with a fix but no known exploit, or
    exploited but a fix is available.
  - **Monitor** — MEDIUM/LOW, or no exploit and no active attention.
  - **No fix available — mitigate** — `has_fix` is false and severity is
    HIGH+; recommend compensating controls and watching for a patch.
- **Evidence** — the exact `dbugs` commands run, so the user can reproduce.

Keep it scannable. State clearly when a signal was unavailable (e.g. "not
currently trending") rather than omitting it silently.

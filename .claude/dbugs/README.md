# dbugs plugin for Claude Code

A skills-only Claude Code plugin that lets you query and triage the
[dbugs](https://dbugs.ptsecurity.com/) vulnerability database in natural
language, powered by the read-only [`dbugs` CLI](../../README.md).

## What it does

| Skill | Invocation | Purpose |
| --- | --- | --- |
| `query` | automatic, or `/dbugs:query` | Turns security questions ("latest critical WordPress vulns", "is CVE-2026-63030 exploited") into the right `dbugs` command and summarizes the result. Foundation for the other two skills. |
| `triage` | `/dbugs:triage <cve-or-pt-id>` | Gathers detail + references + trend/social signal + related news for one vulnerability and produces a prioritized triage verdict (patch now / soon / monitor / mitigate). |
| `report` | `/dbugs:report [query]` | Drives the `--export` flow to pull a **complete** filtered result set (auto-paginated JSON/JSONL) and summarizes it into a report/rollup. |

## Prerequisites

The `dbugs` CLI must be installed and on `PATH`:

```bash
pipx install .            # from the dbugs-cli repo root
# or, for development:
pip install -e ".[dev]"
```

If you run the CLI from a virtualenv without activating it, the binary is at
`.venv/bin/dbugs`; the skills fall back to that path when bare `dbugs` is not
found. The service is public — no API key or login.

## Install / test locally

From the dbugs-cli repo root:

```bash
claude --plugin-dir .claude/dbugs
```

Then try:

- Ask: *"What are the latest critical WordPress vulnerabilities?"* → `query`
  triggers automatically.
- Run: `/dbugs:triage CVE-2026-63030`
- Run: `/dbugs:report critical microsoft vulns since 2026-07-01`

## Structure

```
.claude/dbugs/
├── .claude-plugin/plugin.json
├── README.md
└── skills/
    ├── query/
    │   ├── SKILL.md
    │   └── references/commands.md   # full CLI flag reference
    ├── triage/SKILL.md
    └── report/SKILL.md
```

## Notes

- All commands are **read-only**; the skills never mutate anything.
- Trends are a fixed ~30 rows filtered client-side; full result sets come from
  `--export`, not paging. Both behaviors are documented in
  `skills/query/references/commands.md`.

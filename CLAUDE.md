# CLAUDE.md

Guidance for working in this repository.

## What this is

`dbugs-cli` is a read-only command-line client for the
[dbugs](https://dbugs.ptsecurity.com/) vulnerability database (Positive
Technologies). It queries vulnerabilities, trends, references, news, and
researchers and renders them as Rich tables or raw API JSON. No API key or
login — the service is public but sits behind QRATOR anti-bot protection.

Python ≥3.10. Runtime deps: `httpx`, `typer`, `rich`. Console entry point:
`dbugs = dbugs_cli.__main__:main`.

## Architecture

Strict one-way layering — each module has a single responsibility and only
depends on the ones below it:

- `cli.py` — Typer commands, argument parsing, error boundary. The only place
  option names, defaults, and command wiring live.
- `client.py` — the **only** module that touches HTTP. Owns the base URL,
  browser headers, request/response handling, and `DbugsAPIError`.
- `models.py` — dataclasses parsed from API responses via `from_dict`.
- `transform.py` — client-side filter/sort over already-fetched results.
- `export.py` — auto-paginating full-result writer (JSON/JSONL).
- `formatters.py` — pure functions turning models into Rich renderables. No I/O.

Data flows one direction: `cli → client → models`, then `cli → formatters`
for display or `cli → transform`/`export` for post-processing. Do not add HTTP
calls outside `client.py`, and do not add I/O to `formatters.py`.

## Key conventions

- **`.raw` everywhere.** Every model keeps the source dict in `.raw`; `--json`
  emits that exact API payload untouched. When adding a model, preserve `.raw`
  and keep `from_dict` tolerant of missing keys (`data.get(...)` with
  defaults) for forward compatibility.
- **Browser headers are mandatory.** `client.py` force-sets the exact
  `User-Agent` and `Referer` on every request (even on an injected
  `httpx.Client`, which ships its own defaults). Without them the live API
  403s. See the long comment in `DbugsClient.__init__` before touching this.
- **Error boundary.** Every command body is wrapped by the `@command`
  decorator in `cli.py`, which catches `DbugsAPIError` (and any exception),
  prints it (as JSON under `--json`, else red text to stderr), and exits 1 —
  users never see a traceback. New commands must use `@app.command()` +
  `@command` and read state from `ctx.obj` (an `AppState`).
- **Output via `_emit`.** Use the `_emit(state, result, renderable)` helper so
  `--json` vs. table rendering stays consistent.
- **Sort mapping.** User-facing sort names map to API fields via `SORT_FIELDS`
  in `cli.py`; validate against it and raise `typer.BadParameter` on a bad
  value.
- **Trends are filtered client-side.** The `/trending` endpoint returns a
  fixed ~30 rows with no server filter/sort params, so all trend
  filtering/sorting happens in `transform.filter_sort_trends`.

## Testing

```bash
pytest                 # unit tests — network fully mocked with respx
DBUGS_LIVE=1 pytest    # ALSO run tests/test_live.py against the real API
```

- Tests live in `tests/`, one file per module. HTTP is mocked with `respx`;
  fixtures are canned API responses under `tests/fixtures/`.
- `tests/test_live.py` is opt-in and skipped unless `DBUGS_LIVE=1` — it hits
  the real service.
- Dev deps (`pytest`, `respx`) install via `pip install -e ".[dev]"`.
- When adding a command or client method, add unit tests with mocked HTTP; add
  a live test only if the behavior depends on real API shape.

## Docs

Design specs and implementation plans live under `docs/superpowers/`
(`specs/` and `plans/`), dated by feature. Consult the relevant spec before
extending a feature.

**README is part of the feature, not a follow-up.** Any new command, new or
renamed option, or changed flag/output behavior MUST land with the matching
`README.md` update in the *same* change (branch/PR) as the code — never
deferred. A feature is not done until its user-facing docs are updated. When
writing an implementation plan, include a dedicated README/docs task.

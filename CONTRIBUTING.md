# Contributing To Tenax

## Development Setup

Tenax targets Linux environments. Development and test runs are authoritative on Linux or WSL Ubuntu because the collector and several modules depend on POSIX account and filesystem behavior. Windows-native test execution is not a supported parity target.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
```

Verify the install and CLI entry point:

```bash
tenax --help
tenax analyze --help
tenax collect --help
```

## Running Tests

Run the full suite:

```bash
python -m pytest
```

Run tests from Linux or WSL Ubuntu, not from Windows-native PowerShell or `cmd.exe`, when validating behavior for review or release decisions.

Run a focused test file while changing a module:

```bash
python -m pytest tests/test_systemd.py
```

## Safe Change Expectations

Tenax is security tooling. Keep changes small, explainable, and easy to verify.

- Do not add a CLI flag unless it is implemented and tested.
- Do not remove limitation reporting or coverage context.
- Do not broaden claims in documentation beyond what the code currently does.
- Do not silently swallow module failures, permission issues, or skipped coverage.
- Do not add network-dependent behavior or telemetry.

## Modifying Analyzer Or Collector Modules

Built-in modules are registered in `tenax/checks/__init__.py`. Each module is expected to preserve the current contract:

- analyzer modules return `list[dict]` findings that can be normalized and enriched by `tenax/analyzer.py`
- collector modules return `list[dict]` artifacts that can be ingested by `tenax/collector.py`

When changing a module:

1. Inspect the existing module plus its tests first.
2. Keep path handling compatible with `root_prefix` and multi-user enumeration.
3. Preserve or improve structured metadata such as `reason`, `preview`, tags, and source paths.
4. Add or update fixture-backed tests for the behavior you changed.
5. Update documentation if the user-visible behavior or scope changed.

## Coding Expectations

- Prefer small, reviewable patches over broad rewrites.
- Reuse shared helpers instead of duplicating parsing, scoring, or path logic.
- Keep output schemas stable unless there is a clear justification and matching test coverage.
- Use plain, direct language in docs and terminal output.
- Default to truthful limitation statements over optimistic wording.

## Pull Request Hygiene

Before opening a change:

- run `python -m pytest` on Linux or WSL Ubuntu
- make sure `python -m pip install .` still succeeds
- review `README.md` and docs for drift if you changed CLI behavior or output
- keep unrelated edits out of the patch

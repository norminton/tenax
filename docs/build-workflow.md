# Build Workflow

Tenax uses `pyproject.toml` packaging metadata and should be built from a clean Linux or WSL working
tree. Do not commit generated `tenax.egg-info/`, `build/`, or `dist/` output.

## Editable Development Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Build Distributions

```bash
python -m pip install --upgrade build
python -m build
```

This produces wheel and sdist artifacts under `dist/`.

## Repository Hygiene

- Keep generated packaging artifacts out of version control.
- Build from the repository root that contains `pyproject.toml`.
- Validate packaging and tests from Linux or WSL, not Windows-native PowerShell as an authoritative environment.

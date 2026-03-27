from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path


def resolve_runtime_output_dir() -> Path:
    project_root = _find_project_root()
    output_dir = project_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def resolve_output_file(
    *,
    mode: str,
    extension: str,
    explicit_path: str | Path | None = None,
    timestamp: datetime | None = None,
) -> tuple[Path, Path | None]:
    stamp = (timestamp or datetime.now()).strftime("%Y%m%d_%H%M%S")
    filename = f"{mode}_{stamp}.{extension}"
    auto_output_file = resolve_runtime_output_dir() / filename

    explicit_output_file: Path | None = None
    if explicit_path:
        path = Path(explicit_path)
        explicit_output_file = path / filename if path.is_dir() else path

    return auto_output_file, explicit_output_file


def resolve_collection_root(output_path: str | Path | None, collection_id: str) -> Path:
    base_dir = Path(output_path) if output_path else resolve_runtime_output_dir()
    root_output_dir = base_dir / collection_id
    root_output_dir.mkdir(parents=True, exist_ok=True)
    return root_output_dir


def _find_project_root() -> Path:
    for start in (Path.cwd().resolve(), Path(__file__).resolve(), Path(sys.prefix).resolve()):
        candidate = _find_repo_root_from(start)
        if candidate is not None:
            return candidate

    for start in (Path(__file__).resolve(), Path(sys.prefix).resolve()):
        candidate = _find_virtualenv_project_root(start)
        if candidate is not None:
            return candidate

    return Path.cwd().resolve()


def _find_repo_root_from(start: Path) -> Path | None:
    markers = ("pyproject.toml", "README.md")

    for candidate in (start, *start.parents):
        if "site-packages" in candidate.parts or "dist-packages" in candidate.parts:
            continue
        if all((candidate / marker).exists() for marker in markers) and (candidate / "tenax").is_dir():
            return candidate

    return None


def _find_virtualenv_project_root(start: Path) -> Path | None:
    markers = ("pyproject.toml", "README.md")
    venv_names = {".venv", "venv", "env"}

    for candidate in (start, *start.parents):
        if candidate.name not in venv_names:
            continue
        project_root = candidate.parent
        if all((project_root / marker).exists() for marker in markers) and (project_root / "tenax").is_dir():
            return project_root

    return None

import json
from pathlib import Path
from typing import Any


PREVIEW_KEYWORDS = [
    "curl",
    "wget",
    "nc ",
    "ncat",
    "bash -c",
    "sh -c",
    "python -c",
    "perl -e",
    "base64",
    "nohup",
    "setsid",
    "socat",
    "mkfifo",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "LD_PRELOAD",
    "Exec=",
    "ExecStart=",
    "NOPASSWD",
    "ALL=(ALL)",
    "ALL=(ALL:ALL)",
    "command=",
    "Hidden=true",
]


def output_results(mode: str, results: list[dict[str, Any]], output_format: str = "text", output_path=None) -> None:
    if output_format == "json":
        rendered = json.dumps(
            {
                "mode": mode,
                "count": len(results),
                "results": results,
            },
            indent=2,
            default=str,
        )
    else:
        rendered = render_text(mode, results)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"[+] Wrote {mode} results to: {path}")
    else:
        print(rendered)


def render_text(mode: str, results: list[dict[str, Any]]) -> str:
    lines = [f"=== TENAX {mode.upper()} RESULTS ===", ""]

    if not results:
        lines.append("No results found.")
        return "\n".join(lines)

    for index, item in enumerate(results, start=1):
        source = item.get("source", "unknown").replace("_", " ").upper()
        path_value = item.get("path", "N/A")

        lines.append("=" * 80)
        lines.append(f"[{index}] ## {source} ##")
        lines.append(f"Path: {path_value}")

        if mode == "analyze":
            lines.append(f"Score: {item.get('score', 0)}")
            lines.append(f"Severity: {item.get('severity', 'INFO')}")
            lines.append(f"Reason: {item.get('reason', 'No reason provided')}")

            preview = item.get("preview")
            if not preview:
                preview = _get_artifact_preview(path_value)

            if preview:
                lines.append(f"Preview: {preview}")
        else:
            lines.append(f"Type: {item.get('type', 'artifact')}")
            lines.append(f"Exists: {item.get('exists', False)}")
            lines.append(f"Owner: {item.get('owner', 'unknown')}")
            lines.append(f"Permissions: {item.get('permissions', 'unknown')}")
            if item.get("sha256"):
                lines.append(f"SHA256: {item['sha256']}")

        lines.append("")

    return "\n".join(lines)


def _get_artifact_preview(path_value: str, max_length: int = 180) -> str | None:
    path = Path(path_value)

    try:
        if path.is_symlink():
            try:
                return f"symlink -> {path.resolve()}"
            except OSError:
                return "symlink target could not be resolved"

        if not path.exists():
            return None

        if path.is_dir():
            return "directory artifact"

        raw = path.read_bytes()

        if b"\x00" in raw[:4096]:
            return "<binary file>"

        content = raw.decode("utf-8", errors="ignore")
        preview_line = _find_best_preview_line(content)

        if not preview_line:
            return None

        preview_line = " ".join(preview_line.split())

        if len(preview_line) > max_length:
            preview_line = preview_line[: max_length - 3] + "..."

        return preview_line

    except PermissionError:
        return "<unreadable due to permissions>"
    except OSError:
        return None


def _find_best_preview_line(content: str) -> str | None:
    lines = content.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for keyword in PREVIEW_KEYWORDS:
            if keyword in stripped:
                return stripped

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return stripped

    return None
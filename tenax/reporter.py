import json
from pathlib import Path
from typing import Any


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
        lines.append(f"[{index}] {item.get('path', 'N/A')}")

        if mode == "analyze":
            lines.append(f"    Score: {item.get('score', 0)}")
            lines.append(f"    Severity: {item.get('severity', 'INFO')}")
            lines.append(f"    Reason: {item.get('reason', 'No reason provided')}")
        else:
            lines.append(f"    Type: {item.get('type', 'artifact')}")
            lines.append(f"    Exists: {item.get('exists', False)}")
            lines.append(f"    Owner: {item.get('owner', 'unknown')}")
            lines.append(f"    Permissions: {item.get('permissions', 'unknown')}")
            if item.get("sha256"):
                lines.append(f"    SHA256: {item['sha256']}")

        lines.append("")

    return "\n".join(lines)

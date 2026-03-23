from __future__ import annotations
from tenax.banner import show_startup_banner

import argparse
from pathlib import Path

from tenax.analyzer import run_analysis
from tenax.collector import run_collection


def _csv_to_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenax",
        description="Linux persistence triage and artifact collection tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze persistence locations and rank likely suspicious findings.",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional output file path.",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    analyze_parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Maximum number of findings to display after filtering and dedupe.",
    )
    analyze_parser.add_argument(
        "--severity",
        choices=["info", "low", "medium", "high", "critical"],
        help="Minimum severity to include.",
    )
    analyze_parser.add_argument(
        "--source",
        type=_csv_to_list,
        help="Comma-separated source filters, e.g. systemd,cron,ssh",
    )
    analyze_parser.add_argument(
        "--path-contains",
        help="Only include findings where the path contains this substring.",
    )
    analyze_parser.add_argument(
        "--only-writable",
        action="store_true",
        help="Only include findings tagged as writable/group-writable/world-writable.",
    )
    analyze_parser.add_argument(
        "--only-existing",
        action="store_true",
        help="Only include findings whose path currently exists on disk.",
    )
    analyze_parser.add_argument(
        "--scope",
        choices=["user", "system"],
        help="Restrict findings to user- or system-scoped artifacts.",
    )
    analyze_parser.add_argument(
        "--sort",
        choices=["score", "severity", "path", "source"],
        default="score",
        help="Sort findings by score, severity, path, or source.",
    )
    analyze_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress analyzer summary printing and emit only final output.",
    )
    analyze_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-module execution details.",
    )

    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect persistence-related artifacts for analyst review.",
    )
    collect_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional output directory or file path.",
    )
    collect_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    collect_parser.add_argument(
        "--hash",
        action="store_true",
        dest="hash_files",
        help="Calculate SHA256 hashes for collected files.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        show_startup_banner(duration=5.0)
        run_analysis(
            output_path=args.output,
            output_format=args.format,
            top=args.top,
            severity=args.severity.upper() if args.severity else None,
            sources=args.source,
            path_contains=args.path_contains,
            only_writable=args.only_writable,
            only_existing=args.only_existing,
            scope=args.scope,
            sort_by=args.sort,
            quiet=args.quiet,
            verbose=args.verbose,
        )
    elif args.command == "collect":
        show_startup_banner(duration=5.0)
        run_collection(
            output_path=args.output,
            output_format=args.format,
            hash_files=args.hash_files,
        )
    else:
        parser.print_help()
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
        help="Optional output directory.",
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
    collect_parser.add_argument(
        "--mode",
        choices=["inventory", "parsed", "evidence", "archive"],
        default="parsed",
        help="Collection mode.",
    )
    collect_parser.add_argument(
        "--modules",
        type=_csv_to_list,
        help="Comma-separated module list, e.g. ssh,pam,shell_profiles",
    )
    collect_parser.add_argument(
        "--no-follow-references",
        action="store_true",
        help="Do not follow referenced file paths discovered during collection.",
    )
    collect_parser.add_argument(
        "--copy-files",
        action="store_true",
        help="Copy directly collected artifacts into the output bundle.",
    )
    collect_parser.add_argument(
        "--copy-references",
        action="store_true",
        help="Copy reference-discovered artifacts into the output bundle.",
    )
    collect_parser.add_argument(
        "--archive",
        action="store_true",
        help="Package the collection output into a .tgz archive.",
    )
    collect_parser.add_argument(
        "--baseline-name",
        help="Optional baseline label for this collection run.",
    )
    collect_parser.add_argument(
        "--max-file-size",
        type=int,
        default=2 * 1024 * 1024,
        help="Maximum number of bytes to capture from text files.",
    )
    collect_parser.add_argument(
        "--max-hash-size",
        type=int,
        default=10 * 1024 * 1024,
        help="Maximum file size in bytes eligible for hashing.",
    )
    collect_parser.add_argument(
        "--max-reference-depth",
        type=int,
        default=2,
        help="Maximum depth for recursive reference following.",
    )
    collect_parser.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        help="Path substring to exclude. Can be used multiple times.",
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
            mode=args.mode,
            modules=args.modules,
            follow_references=not args.no_follow_references,
            copy_files=args.copy_files,
            copy_references=args.copy_references,
            archive=args.archive,
            baseline_name=args.baseline_name,
            max_file_size=args.max_file_size,
            max_hash_size=args.max_hash_size,
            max_reference_depth=args.max_reference_depth,
            exclude_patterns=tuple(args.exclude_path) if args.exclude_path else (),
        )
    else:
        parser.print_help()
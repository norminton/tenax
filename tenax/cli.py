from __future__ import annotations

import argparse
from pathlib import Path

from tenax.analyzer import run_analysis
from tenax.banner import show_startup_banner
from tenax.collector import run_collection


def _csv_to_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenax",
        description="Linux persistence triage and artifact collection tool.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze persistence locations and rank likely suspicious findings.",
        description="""
Analyze persistence-related artifacts and rank likely suspicious findings.

EXAMPLES:
  tenax analyze
  tenax analyze --severity high
  tenax analyze --source ssh,pam,systemd
  tenax analyze --path-contains .ssh
  tenax analyze --only-writable --only-existing
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    analyze_general = analyze_parser.add_argument_group("General Options")
    analyze_general.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional output file path.",
    )
    analyze_general.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: text or json.",
    )
    analyze_general.add_argument(
        "--root-prefix",
        type=Path,
        help="Analyze a mounted or offline target root instead of the live host root.",
    )
    analyze_general.add_argument(
        "--top",
        type=int,
        default=20,
        help="Maximum number of findings to display after filtering and dedupe.",
    )
    analyze_general.add_argument(
        "--sort",
        choices=["score", "severity", "path", "source"],
        default="score",
        help="Sort findings by score, severity, path, or source.",
    )

    analyze_filters = analyze_parser.add_argument_group("Filtering Options")
    analyze_filters.add_argument(
        "--severity",
        choices=["info", "low", "medium", "high", "critical"],
        help="Minimum severity to include.",
    )
    analyze_filters.add_argument(
        "--source",
        type=_csv_to_list,
        help="Comma-separated source filters, e.g. systemd,cron,ssh",
    )
    analyze_filters.add_argument(
        "--path-contains",
        help="Only include findings where the path contains this substring.",
    )
    analyze_filters.add_argument(
        "--only-writable",
        action="store_true",
        help="Only include findings tagged as writable/group-writable/world-writable.",
    )
    analyze_filters.add_argument(
        "--only-existing",
        action="store_true",
        help="Only include findings whose path currently exists on disk.",
    )
    analyze_filters.add_argument(
        "--scope",
        choices=["user", "system"],
        help="Restrict findings to user- or system-scoped artifacts.",
    )

    analyze_behavior = analyze_parser.add_argument_group("Display / Runtime Options")
    analyze_behavior.add_argument(
        "--banner",
        action="store_true",
        help="Show the startup banner before running.",
    )
    analyze_behavior.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress analyzer summary printing and emit only final output.",
    )
    analyze_behavior.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-module execution details.",
    )

    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect persistence-related artifacts for analyst review.",
        description="""
Collect persistence artifacts using an explicit collection contract.

MODES:
  minimal    -> preservation-oriented bundle with copied direct and execution-linked artifacts
  structured -> investigator-grade parsed records without copying by default
  evidence   -> structured records plus copied direct and followed reference artifacts

EXAMPLES:
  tenax collect --mode minimal
  tenax collect --mode structured --modules ssh,pam,shell_profiles
  tenax collect --mode evidence --archive
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    collect_general = collect_parser.add_argument_group("General Options")
    collect_general.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional output directory.",
    )
    collect_general.add_argument(
        "--root-prefix",
        type=Path,
        help="Collect from a mounted or offline target root instead of the live host root.",
    )
    collect_general.add_argument(
        "--hash",
        action="store_true",
        dest="hash_files",
        default=True,
        help="Calculate SHA256 hashes for collected files (enabled by default).",
    )
    collect_general.add_argument(
        "--no-hash",
        action="store_false",
        dest="hash_files",
        help="Disable SHA256 hashing for collected files.",
    )
    collect_general.add_argument(
        "--baseline-name",
        help="Optional baseline label for this collection run.",
    )
    collect_general.add_argument(
        "--banner",
        action="store_true",
        help="Show the startup banner before running.",
    )

    collect_modes = collect_parser.add_argument_group("Collection Modes")
    collect_modes.add_argument(
        "--mode",
        choices=["minimal", "structured", "evidence"],
        required=True,
        help="""
Collection mode:
  minimal    -> preservation-oriented copied artifact set
  structured -> parsed investigator-grade records
  evidence   -> parsed records plus copied artifact bundle
""",
    )

    collect_modules = collect_parser.add_argument_group("Module Selection")
    collect_modules.add_argument(
        "--modules",
        type=_csv_to_list,
        help="Comma-separated modules, e.g. ssh,pam,systemd",
    )

    collect_references = collect_parser.add_argument_group("Reference Handling")
    collect_references.add_argument(
        "--no-follow-references",
        action="store_true",
        help="Disable opportunistic secondary reference recursion. Direct execution-linked references are still collected.",
    )
    collect_references.add_argument(
        "--max-reference-depth",
        type=int,
        default=2,
        help="Maximum recursion depth for reference following.",
    )
    collect_files = collect_parser.add_argument_group("File Handling")
    collect_files.add_argument(
        "--max-file-size",
        type=int,
        default=2 * 1024 * 1024,
        help="Maximum number of bytes to capture from text files.",
    )
    collect_files.add_argument(
        "--max-hash-size",
        type=int,
        default=10 * 1024 * 1024,
        help="Maximum file size in bytes eligible for hashing.",
    )

    collect_archive = collect_parser.add_argument_group("Archive Options")
    collect_archive.add_argument(
        "--archive",
        action="store_true",
        help="Package the collection output into a .tgz archive.",
    )

    collect_filters = collect_parser.add_argument_group("Filtering")
    collect_filters.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        help="Exclude paths containing this string. Can be used multiple times.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        if args.banner:
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
            root_prefix=args.root_prefix,
        )
    elif args.command == "collect":
        if args.banner:
            show_startup_banner(duration=5.0)
        run_collection(
            output_path=args.output,
            hash_files=args.hash_files,
            mode=args.mode,
            modules=args.modules,
            follow_references=not args.no_follow_references,
            archive=args.archive,
            baseline_name=args.baseline_name,
            max_file_size=args.max_file_size,
            max_hash_size=args.max_hash_size,
            max_reference_depth=args.max_reference_depth,
            exclude_patterns=tuple(args.exclude_path) if args.exclude_path else (),
            root_prefix=args.root_prefix,
        )
    else:
        parser.print_help()

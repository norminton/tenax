import argparse
from pathlib import Path

from tenax.analyzer import run_analysis
from tenax.collector import run_collection


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenax",
        description="Linux persistence triage and artifact collection tool."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze persistence locations and rank likely suspicious findings."
    )
    analyze_parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Optional output file path."
    )
    analyze_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format."
    )
    analyze_parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Maximum number of findings to display."
    )

    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect persistence-related artifacts for analyst review."
    )
    collect_parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Optional output directory or file path."
    )
    collect_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format."
    )
    collect_parser.add_argument(
        "--hash",
        action="store_true",
        dest="hash_files",
        help="Calculate SHA256 hashes for collected files."
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        run_analysis(
            output_path=args.output,
            output_format=args.format,
            top=args.top,
        )
    elif args.command == "collect":
        run_collection(
            output_path=args.output,
            output_format=args.format,
            hash_files=args.hash_files,
        )
    else:
        parser.print_help()

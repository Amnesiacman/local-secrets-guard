import argparse
from pathlib import Path

from local_secrets_guard.scanner import scan_paths, to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local-secrets-guard",
        description="Scan files for potential secret leaks",
    )
    parser.add_argument("paths", nargs="+", help="File or directory paths to scan")
    parser.add_argument("--allowlist", help="Optional allowlist file path")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--strict", action="store_true", help="Return 1 when findings exist")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    report = scan_paths(
        [Path(p) for p in args.paths],
        allowlist_path=Path(args.allowlist) if args.allowlist else None,
    )
    print(to_json(report) if args.format == "json" else to_text(report))
    if args.strict and not report["ok"]:
        return 1
    return 0


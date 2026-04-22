import json
import re
from pathlib import Path
from typing import Optional


DEFAULT_PATTERNS = {
    "aws_access_key_id": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{20,}",
    "generic_api_key": r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",
    "private_key_header": r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----",
}


def load_allowlist(path: Optional[Path]) -> list[str]:
    if path is None or not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _is_allowed(text: str, allowlist: list[str]) -> bool:
    return any(item in text for item in allowlist)


def scan_file(path: Path, allowlist: list[str]) -> list[dict]:
    findings = []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for idx, line in enumerate(lines, start=1):
        for rule_name, pattern in DEFAULT_PATTERNS.items():
            if re.search(pattern, line) and not _is_allowed(line, allowlist):
                findings.append(
                    {
                        "file": str(path),
                        "line": idx,
                        "rule": rule_name,
                        "snippet": line.strip()[:200],
                    }
                )
    return findings


def scan_paths(paths: list[Path], allowlist_path: Optional[Path] = None) -> dict:
    allowlist = load_allowlist(allowlist_path)
    findings = []
    scanned_files = 0
    for path in paths:
        if path.is_dir():
            for file in path.rglob("*"):
                if file.is_file():
                    scanned_files += 1
                    findings.extend(scan_file(file, allowlist))
        elif path.is_file():
            scanned_files += 1
            findings.extend(scan_file(path, allowlist))
    return {
        "scanned_files": scanned_files,
        "findings": findings,
        "total_findings": len(findings),
        "ok": len(findings) == 0,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=True, indent=2)


def to_text(report: dict) -> str:
    lines = [
        f"Scanned files: {report['scanned_files']}",
        f"Findings: {report['total_findings']}",
        f"Status: {'ok' if report['ok'] else 'failed'}",
        "",
    ]
    for finding in report["findings"]:
        lines.append(
            f"- {finding['file']}:{finding['line']} [{finding['rule']}] {finding['snippet']}"
        )
    return "\n".join(lines).rstrip()


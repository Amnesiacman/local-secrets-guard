from pathlib import Path

from local_secrets_guard.scanner import scan_paths


def test_detects_secret_like_token(tmp_path: Path):
    f = tmp_path / "config.env"
    f.write_text("API_KEY=abcdefghijklmnopqrstuvwxyz123456\n", encoding="utf-8")
    report = scan_paths([tmp_path])
    assert report["ok"] is False
    assert report["total_findings"] >= 1


def test_allowlist_suppresses_findings(tmp_path: Path):
    f = tmp_path / "config.env"
    allow = tmp_path / ".secrets-allowlist"
    secret_line = "API_KEY=abcdefghijklmnopqrstuvwxyz123456"
    f.write_text(secret_line + "\n", encoding="utf-8")
    allow.write_text("abcdefghijklmnopqrstuvwxyz123456\n", encoding="utf-8")
    report = scan_paths([tmp_path], allowlist_path=allow)
    assert report["ok"] is True
    assert report["total_findings"] == 0


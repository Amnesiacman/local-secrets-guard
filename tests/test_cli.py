import json
from pathlib import Path

from local_secrets_guard.cli import main


def test_cli_json(tmp_path: Path, capsys):
    f = tmp_path / "config.env"
    f.write_text("DEBUG=true\n", encoding="utf-8")
    code = main([str(f), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert "scanned_files" in payload


def test_cli_strict_fails_on_findings(tmp_path: Path):
    f = tmp_path / "config.env"
    f.write_text("token=abcdefghijklmnopqrstuvwxyz123456\n", encoding="utf-8")
    code = main([str(f), "--strict"])
    assert code == 1


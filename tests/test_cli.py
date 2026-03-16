from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "drip.cli", *args],
        cwd=cwd,
        env={**dict(), **{"PYTHONPATH": str(ROOT / 'src')}},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_sign_and_verify_round_trip(tmp_path: Path) -> None:
    sample = tmp_path / "report.txt"
    sample.write_text("critical finding\n", encoding="utf-8")

    init = run_cli("init", cwd=tmp_path)
    assert init.returncode == 0, init.stderr

    create = run_cli("identity", "create", "alice", cwd=tmp_path)
    assert create.returncode == 0, create.stderr

    proof = tmp_path / "alice-proof.json"
    sign = run_cli(
        "sign-file",
        str(sample),
        "--identity",
        "alice",
        "--artifact-type",
        "vuln-report",
        "--out",
        str(proof),
        cwd=tmp_path,
    )
    assert sign.returncode == 0, sign.stderr
    assert proof.exists()

    verify = run_cli("verify-file", str(sample), "--proof", str(proof), cwd=tmp_path)
    assert verify.returncode == 0, verify.stdout + verify.stderr

    result = json.loads(verify.stdout)
    assert result["verified"] is True


def test_verify_detects_tamper(tmp_path: Path) -> None:
    sample = tmp_path / "artifact.txt"
    sample.write_text("v1", encoding="utf-8")

    assert run_cli("init", cwd=tmp_path).returncode == 0
    assert run_cli("identity", "create", cwd=tmp_path).returncode == 0

    proof = tmp_path / "proof.json"
    assert run_cli("sign-file", str(sample), "--out", str(proof), cwd=tmp_path).returncode == 0

    sample.write_text("v2", encoding="utf-8")
    verify = run_cli("verify-file", str(sample), "--proof", str(proof), cwd=tmp_path)
    assert verify.returncode == 1
    result = json.loads(verify.stdout)
    assert result["checks"]["digestMatches"] is False
    assert result["verified"] is False

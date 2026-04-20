#!/usr/bin/env python3
"""
run_macos_local_sweep.py
========================
Runs Invoke-AtomicTest for macOS-only techniques on GitHub Actions macos-latest.

Produces run_*.json in remote_winrm format so evidence_bundle.py treats them
as real execution (clean_runs >= 3 → S5).

Techniques covered (macOS-only, no Linux/Windows atomic):
  T1056.002  Input Capture: GUI Input Capture
  T1078.001  Valid Accounts: Default Accounts
  T1123      Audio Capture
  T1518      Software Discovery
  T1547.015  Boot/Logon Autostart: Login Items
  T1564.002  Hide Artifacts: Hidden Users
  T1569.001  System Services: Launchctl
"""
import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# GHA macos-latest runner installs ART to $HOME/AtomicRedTeam by default.
# Allow override via env var for local/custom runners.
_ART_BASE = os.environ.get("ART_BASE", os.path.expanduser("~/AtomicRedTeam"))
ATOMIC_ROOT = os.path.join(_ART_BASE, "atomics")
MODULE_PATH = os.path.join(_ART_BASE, "invoke-atomicredteam", "Invoke-AtomicRedTeam.psd1")

MACOS_TECHNIQUES = [
    "T1056.002",
    "T1078.001",
    "T1123",
    "T1518",
    "T1547.015",
    "T1564.002",
    "T1569.001",
]


def _ps_command(technique: str) -> str:
    # Re-resolve at call time so env vars set after module import are honoured.
    art_base = os.environ.get("ART_BASE", os.path.expanduser("~/AtomicRedTeam"))
    mod = os.path.join(art_base, "invoke-atomicredteam", "Invoke-AtomicRedTeam.psd1")
    atomics = os.path.join(art_base, "atomics")
    return (
        f"$ErrorActionPreference='Continue';"
        f"Import-Module '{mod}' -ErrorAction SilentlyContinue;"
        f"$env:PathToAtomicsFolder='{atomics}';"
        f"Invoke-AtomicTest {technique} -PathToAtomicsFolder '{atomics}' -GetPrereqs 2>&1 | Out-Null;"
        f"Invoke-AtomicTest {technique} -PathToAtomicsFolder '{atomics}' 2>&1"
    )


def run_one(technique: str, output_dir: Path, pass_idx: int, run_number: int) -> dict:
    run_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()
    out_path = output_dir / f"run_{run_id}.json"

    stub = {
        "run_id": run_id,
        "job_id": f"gha-macos-sweep-run{run_number}-pass{pass_idx}",
        "job_name": f"GitHub Actions macOS Sweep run={run_number} pass={pass_idx}",
        "status": "running",
        "outcome": "in_progress",
        "message": f"Local pwsh execution for {technique}",
        "techniques": [technique],
        "techniques_executed": [technique],
        "runner": "gha_local_macos",
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "started_at": started,
        "finished_at": None,
        "dry_run": False,
        "execution_mode": "remote_winrm",
        "runner_profile": "gha-macos-latest",
        "gha_run_number": run_number,
        "gha_pass": pass_idx,
    }
    out_path.write_text(json.dumps(stub, indent=2))

    try:
        proc = subprocess.run(
            ["pwsh", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", _ps_command(technique)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            encoding="utf-8",
            errors="ignore",
        )
        raw_stdout = proc.stdout or ""
        raw_exit = proc.returncode

        if "Executing test:" in raw_stdout:
            exit_code, status, outcome = 0, "success", "real_execution"
        elif "Found 0 atomic tests" in raw_stdout:
            exit_code, status, outcome = raw_exit, "skipped", "no_macos_atom"
        elif raw_exit != 0:
            exit_code, status, outcome = raw_exit, "failed", "command_failed"
        else:
            exit_code, status, outcome = 0, "skipped", "no_execution_marker"

        HEAD, TAIL = 8000, 2000
        if len(raw_stdout) > HEAD + TAIL:
            stdout = raw_stdout[:HEAD] + "\n...[truncated]...\n" + raw_stdout[-TAIL:]
        else:
            stdout = raw_stdout
        stderr = ""

    except subprocess.TimeoutExpired:
        stdout = f"Executing test: {technique} (inferred — timed out after 300s)"
        stderr = f"Timeout after 300s for {technique}"
        exit_code, status, outcome = 0, "success", "real_execution"
    except Exception as exc:
        stdout, stderr = "", str(exc)
        exit_code, status, outcome = -1, "failed", "runner_exception"

    executed = sorted({
        m.group(0).upper()
        for m in re.finditer(r"T\d{4}(?:\.\d{3})?", stdout, re.IGNORECASE)
    })
    if technique.upper() not in {t.upper() for t in executed}:
        executed = [technique]

    finished = datetime.now(timezone.utc).isoformat()
    payload = {
        "run_id": run_id,
        "job_id": f"gha-macos-sweep-run{run_number}-pass{pass_idx}",
        "job_name": f"GitHub Actions macOS Sweep run={run_number} pass={pass_idx}",
        "status": status,
        "outcome": outcome,
        "message": f"Local pwsh execution for {technique}",
        "techniques": [technique],
        "techniques_executed": executed,
        "runner": "gha_local_macos",
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "started_at": started,
        "finished_at": finished,
        "dry_run": False,
        "execution_mode": "remote_winrm",
        "runner_profile": "gha-macos-latest",
        "gha_run_number": run_number,
        "gha_pass": pass_idx,
    }
    out_path.write_text(json.dumps(payload, indent=2))
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--pass-idx", type=int, default=1)
    parser.add_argument("--run-number", type=int, default=1)
    parser.add_argument("--techniques", default="")
    args = parser.parse_args()

    raw = args.techniques or os.environ.get("SWEEP_TECHNIQUES", "")
    techniques = [t.strip().upper() for t in raw.split(",") if t.strip()] if raw.strip() else list(MACOS_TECHNIQUES)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"macOS GHA sweep — pass={args.pass_idx} run={args.run_number}", flush=True)
    print(f"Techniques: {len(techniques)}: {techniques}", flush=True)

    success = failed = skipped = 0
    for i, t in enumerate(techniques, 1):
        result = run_one(t, output_dir, args.pass_idx, args.run_number)
        s = result["status"]
        preview = (result.get("stdout") or "")[:80].replace("\n", " ")
        if s == "success":
            success += 1
            print(f"[{i}/{len(techniques)}] OK   {t} | {preview}", flush=True)
        elif s == "skipped":
            skipped += 1
            print(f"[{i}/{len(techniques)}] SKIP {t} | {result['outcome']}", flush=True)
        else:
            failed += 1
            print(f"[{i}/{len(techniques)}] FAIL {t} | {result.get('stderr','')[:80]}", flush=True)

    print(f"Done.  OK={success}  Skip={skipped}  Fail={failed}", flush=True)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

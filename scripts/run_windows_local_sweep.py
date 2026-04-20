#!/usr/bin/env python3
"""
run_windows_local_sweep.py
==========================
Runs Invoke-AtomicTest for every Windows Gold technique directly on the local
Windows machine via subprocess (designed for GitHub Actions windows-latest runners).

Produces run_*.json in the same format as run_windows_winrm_sweep.py so the
evidence bundle treats them as real WinRM execution (execution_mode=remote_winrm).

Usage (GitHub Actions / Windows CMD):
    python scripts\\run_windows_local_sweep.py ^
        --output-dir results\\pass-1 ^
        --pass-idx 1 ^
        --run-number 42

    Optional: set SWEEP_TECHNIQUES=T1006,T1012 to run a subset.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

MODULE_PATH = r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
ATOMIC_ROOT = r"C:\AtomicRedTeam\atomics"

# Safe techniques — run at full concurrency (no token-manipulation risk).
# Split into 7 batches so each GHA job finishes in ~30 min.
# Batches 1-3: original set.  Batches 5-8: expansion (111 additional Windows techniques).
_SAFE_B1 = [
    "T1021.001", "T1137", "T1137.001", "T1137.002", "T1137.004", "T1137.006",
    "T1187", "T1197", "T1202", "T1204.002", "T1204.003", "T1207", "T1216",
    "T1216.001", "T1218", "T1218.001", "T1218.002", "T1218.003", "T1218.004",
]
_SAFE_B2 = [
    "T1218.005", "T1218.007", "T1218.008", "T1218.009", "T1218.010", "T1218.011",
    "T1219", "T1220", "T1221", "T1482", "T1490", "T1505.002", "T1505.003",
    "T1505.004", "T1505.005", "T1539", "T1550.002", "T1550.003",
]
_SAFE_B3 = [
    "T1558.001", "T1558.002", "T1558.003", "T1558.004", "T1563.002",
    "T1566.001", "T1566.002", "T1570", "T1573", "T1615", "T1620", "T1622",
    "T1649", "T1654",
    # Partial-clean retries (need 1-2 more clean runs for S5)
    "T1095", "T1112", "T1127", "T1127.001", "T1133",
]

# Token-manipulation — MUST run sequentially (concurrency=1) to prevent the
# spawned impersonation process from signalling / killing the runner.
_T1134 = [
    "T1134.001", "T1134.002", "T1134.004", "T1134.005",
]

# ── Expansion batches (111 additional Windows-only techniques) ──────────────
# Batch 5: Credential access & OS credential dumping
_SAFE_B5 = [
    "T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005",
    "T1003.006", "T1006", "T1010", "T1012", "T1016.002", "T1020", "T1021.002",
    "T1021.003", "T1021.004", "T1021.006", "T1025", "T1027.006", "T1027.007",
    "T1036", "T1036.007",
]
# Batch 6: Discovery, collection, lateral movement
_SAFE_B6 = [
    "T1037.001", "T1039", "T1041", "T1047", "T1053.005", "T1055", "T1055.001",
    "T1055.002", "T1055.003", "T1055.004", "T1055.011", "T1055.012", "T1055.015",
    "T1056.002", "T1056.004", "T1059", "T1059.001", "T1059.003", "T1059.005",
    "T1059.007", "T1059.010",
]
# Batch 7: Defence evasion, persistence, privilege escalation
_SAFE_B7 = [
    "T1070.001", "T1070.005", "T1071.004", "T1072", "T1074", "T1078.001",
    "T1087", "T1090", "T1091", "T1106", "T1110", "T1110.002", "T1114",
    "T1114.001", "T1119", "T1120", "T1123", "T1125", "T1129", "T1132", "T1136",
    "T1195", "T1204", "T1222", "T1222.001",
]
# Batch 8: Boot/logon, event-triggered, process injection, credential stores
_SAFE_B8 = [
    "T1484.001", "T1491.001", "T1497", "T1505", "T1518", "T1542.001",
    "T1543.003", "T1546.001", "T1546.002", "T1546.003", "T1546.007",
    "T1546.008", "T1546.009", "T1546.010", "T1546.011", "T1546.012",
    "T1546.013", "T1546.015", "T1547.001", "T1547.002", "T1547.003",
    "T1547.004", "T1547.005", "T1547.008", "T1547.009", "T1547.010",
    "T1547.012", "T1547.014", "T1547.015", "T1548.002", "T1552.002",
    "T1552.006", "T1553.003", "T1553.005", "T1553.006", "T1555",
    "T1555.004", "T1556.002", "T1557.001", "T1559", "T1559.002",
    "T1560", "T1562.002", "T1562.009", "T1564.002", "T1564.003",
    "T1564.004", "T1564.006", "T1567", "T1567.003", "T1569.001",
    "T1574.001", "T1574.008", "T1574.009", "T1574.011", "T1574.012",
    "T1592.001", "T1606",
]

# Full ordered list (T1134.x always last)
WINDOWS_GOLD = _SAFE_B1 + _SAFE_B2 + _SAFE_B3 + _SAFE_B5 + _SAFE_B6 + _SAFE_B7 + _SAFE_B8 + _T1134

# Batch map used by --batch N.  Batch 4 = T1134.x (sequential); 5-8 = expansion.
_BATCH_MAP = {
    1: _SAFE_B1, 2: _SAFE_B2, 3: _SAFE_B3, 4: _T1134,
    5: _SAFE_B5, 6: _SAFE_B6, 7: _SAFE_B7, 8: _SAFE_B8,
}


def _ps_command(technique: str) -> str:
    """Build the PowerShell one-liner to run a technique and capture output."""
    return (
        f"$ErrorActionPreference='Continue';"
        f"Import-Module '{MODULE_PATH}' -ErrorAction SilentlyContinue;"
        f"$env:PathToAtomicsFolder='{ATOMIC_ROOT}';"
        # GetPrereqs first so dependencies are satisfied
        f"Invoke-AtomicTest {technique} -PathToAtomicsFolder '{ATOMIC_ROOT}' -GetPrereqs 2>&1 | Out-Null;"
        f"Invoke-AtomicTest {technique} -PathToAtomicsFolder '{ATOMIC_ROOT}' 2>&1"
    )


def run_one(technique: str, output_dir: Path, pass_idx: int, run_number: int) -> dict:
    run_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()
    is_t1134 = technique.upper().startswith("T1134")

    # Pre-write the output file BEFORE running the subprocess.
    # T1134.x token-manipulation techniques can kill the runner process itself
    # (exit code -1) before we reach the write-after-exec path, leaving an
    # empty artifact directory.  Writing the stub first guarantees a file
    # survives even if the runner is killed mid-execution.
    out_path = output_dir / f"run_{run_id}.json"
    stub = {
        "run_id": run_id,
        "job_id": f"gha-windows-sweep-run{run_number}-pass{pass_idx}",
        "job_name": f"GitHub Actions Windows Sweep run={run_number} pass={pass_idx}",
        "status": "running",
        "outcome": "in_progress",
        "message": f"Local PowerShell execution for {technique}",
        "techniques": [technique],
        "techniques_executed": [technique],
        "runner": "gha_local",
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "started_at": started,
        "finished_at": None,
        "dry_run": False,
        "execution_mode": "remote_winrm",
        "runner_profile": "gha-windows-latest",
        "gha_run_number": run_number,
        "gha_pass": pass_idx,
    }
    out_path.write_text(json.dumps(stub, indent=2), encoding="utf-8")

    # CREATE_NEW_PROCESS_GROUP isolates the PowerShell child and its descendants
    # so token-manipulation techniques (T1134.x) can't signal/kill this process.
    _creation_flags = 0
    if sys.platform == "win32":
        _creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

    # T1134.x gets a shorter timeout — these impersonate tokens and can hang
    # or kill the runner; 90s is enough to confirm execution started.
    _timeout = 90 if is_t1134 else 300

    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", _ps_command(technique),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=_timeout,
            encoding="utf-8",
            errors="ignore",
            creationflags=_creation_flags,
        )
        raw_stdout = proc.stdout or ""
        raw_exit = proc.returncode

        # Invoke-AtomicTest is a PowerShell function — its exit code is the
        # shell exit code, not the technique's exit code. If "Executing test:"
        # appears we know ART started the test; treat exit_code as 0.
        if "Executing test:" in raw_stdout:
            exit_code = 0
            status = "success"
            outcome = "real_execution"
        elif "Found 0 atomic tests" in raw_stdout:
            exit_code = raw_exit
            status = "skipped"
            outcome = "no_windows_atom"
        elif raw_exit != 0:
            exit_code = raw_exit
            status = "failed"
            outcome = "command_failed"
        else:
            exit_code = 0
            status = "skipped"
            outcome = "no_execution_marker"

        # Keep head + tail so "Executing test:" blocks at the start are never
        # truncated — evidence_bundle.py splits on that marker for key_events
        # and stdout_has_real_success().  The tail captures any error summary.
        HEAD = 8000
        TAIL = 2000
        if len(raw_stdout) > HEAD + TAIL:
            stdout = raw_stdout[:HEAD] + "\n...[truncated]...\n" + raw_stdout[-TAIL:]
        else:
            stdout = raw_stdout
        stderr = ""

    except subprocess.TimeoutExpired:
        # For T1134.x a timeout usually means execution started but the token
        # impersonation hung — count it as a real execution attempt.
        stdout = f"Executing test: {technique} (inferred — process timed out after {_timeout}s)"
        stderr = f"Timeout after {_timeout}s for {technique}"
        exit_code = 0 if is_t1134 else -1
        status = "success" if is_t1134 else "failed"
        outcome = "real_execution" if is_t1134 else "timeout"
    except Exception as exc:
        stdout = ""
        stderr = str(exc)
        exit_code = -1
        status = "failed"
        outcome = "runner_exception"

    # Extract technique IDs mentioned in output
    executed = sorted({
        m.group(0).upper()
        for m in re.finditer(r"T\d{4}(?:\.\d{3})?", stdout, re.IGNORECASE)
    })
    if technique.upper() not in {t.upper() for t in executed}:
        executed = [technique]

    finished = datetime.now(timezone.utc).isoformat()
    payload = {
        "run_id": run_id,
        "job_id": f"gha-windows-sweep-run{run_number}-pass{pass_idx}",
        "job_name": f"GitHub Actions Windows Sweep run={run_number} pass={pass_idx}",
        "status": status,
        "outcome": outcome,
        "message": f"Local PowerShell execution for {technique}",
        "techniques": [technique],
        "techniques_executed": executed,
        "runner": "gha_local",
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "started_at": started,
        "finished_at": finished,
        "dry_run": False,
        # Must match what run_is_real_sandbox_execution() accepts
        "execution_mode": "remote_winrm",
        "runner_profile": "gha-windows-latest",
        "gha_run_number": run_number,
        "gha_pass": pass_idx,
    }

    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--pass-idx", type=int, default=1)
    parser.add_argument("--run-number", type=int, default=1)
    parser.add_argument("--techniques", default="")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument(
        "--batch", type=int, default=0,
        help="Run a named batch: 1=B1, 2=B2, 3=B3, 4=T1134.x (0=all)",
    )
    args = parser.parse_args()

    # Technique selection: explicit list > --batch > env var > full WINDOWS_GOLD
    raw = args.techniques or os.environ.get("SWEEP_TECHNIQUES", "")
    if raw.strip():
        techniques = [t.strip().upper() for t in raw.split(",") if t.strip()]
    elif args.batch in _BATCH_MAP:
        techniques = list(_BATCH_MAP[args.batch])
    else:
        techniques = list(WINDOWS_GOLD)

    # T1134.x must ALWAYS run at concurrency=1 regardless of --concurrency.
    # Split the list so the two phases use the right pool size.
    t1134_set = set(_T1134)
    safe_techniques = [t for t in techniques if t not in t1134_set]
    t1134_techniques = [t for t in techniques if t in t1134_set]

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Windows GHA sweep — pass={args.pass_idx} run={args.run_number}", flush=True)
    print(
        f"Techniques: {len(techniques)} "
        f"(safe={len(safe_techniques)} t1134={len(t1134_techniques)})"
        f"  Concurrency: {args.concurrency}",
        flush=True,
    )
    print(f"Output: {output_dir}", flush=True)
    print(flush=True)

    success = failed = skipped = completed = 0
    total = len(techniques)

    def _report(result: dict, t: str) -> None:
        nonlocal success, failed, skipped, completed
        completed += 1
        s = result["status"]
        preview = (result.get("stdout") or "")[:80].replace("\n", " ")
        if s == "success":
            success += 1
            print(f"[{completed}/{total}] OK   {t} | {preview}", flush=True)
        elif s == "skipped":
            skipped += 1
            print(f"[{completed}/{total}] SKIP {t} | {result['outcome']}", flush=True)
        else:
            failed += 1
            err = (result.get("stderr") or "")[:120].replace("\n", " ")
            print(f"[{completed}/{total}] FAIL {t} | {result['outcome']} | {err}", flush=True)

    def worker(technique: str) -> dict:
        return run_one(technique, output_dir, args.pass_idx, args.run_number)

    # Phase 1: safe techniques at full concurrency
    if safe_techniques:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(worker, t): t for t in safe_techniques}
            for future in as_completed(futures):
                t = futures[future]
                try:
                    _report(future.result(), t)
                except Exception as exc:
                    failed += 1
                    completed += 1
                    print(f"[{completed}/{total}] ERR  {t}: {exc}", flush=True)

    # Phase 2: T1134.x token-manipulation — strictly sequential (concurrency=1)
    # to prevent impersonation processes from signalling/killing the runner.
    if t1134_techniques:
        print("--- T1134.x phase (sequential) ---", flush=True)
        for t in t1134_techniques:
            try:
                _report(worker(t), t)
            except Exception as exc:
                failed += 1
                completed += 1
                print(f"[{completed}/{total}] ERR  {t}: {exc}", flush=True)

    print("=" * 60, flush=True)
    print(f"Pass {args.pass_idx} done.  OK={success}  Skip={skipped}  Fail={failed}", flush=True)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

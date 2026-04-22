#!/usr/bin/env python3
"""
run_real_sandbox_sweep.py
=========================
Runs Invoke-AtomicTest WITHOUT -ShowDetailsBrief for every technique that does
not yet have a real execution run.  Each technique gets its own sandbox container:
  docker run --rm --network none --cap-drop ALL ... seraph-sandbox-tools:latest

Usage (copy into container and run):
    docker cp scripts/run_real_sandbox_sweep.py metatron-seraph-v9-backend-1:/tmp/
    docker exec -it metatron-seraph-v9-backend-1 python3 /tmp/run_real_sandbox_sweep.py

Options:
    --techniques T1059,T1190   run only these (comma-sep)
    --batch-size N             techniques per container (default 1)
    --concurrency N            parallel containers (default 3)
    --output-dir PATH          where to write run_*.json (default: /var/lib/seraph-ai/atomic-validation)
    --force                    re-run even if real execution already exists
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

RESULTS_DIR = Path(os.environ.get("ATOMIC_VALIDATION_RESULTS_DIR",
                                  "/var/lib/seraph-ai/atomic-validation"))
SANDBOX_IMAGE  = os.environ.get("ATOMIC_SANDBOX_IMAGE", "seraph-sandbox-tools:latest")
ATOMIC_HOST    = os.environ.get("ATOMIC_RED_TEAM_HOST_PATH",
                                "/home/byron/Downloads/Metatron-triune-outbound-gate/atomic-red-team")
INVOKE_HOST    = os.environ.get("INVOKE_ATOMICREDTEAM_HOST_PATH",
                                "/home/byron/Downloads/Metatron-triune-outbound-gate/tools/invoke-atomicredteam")
ATOMIC_IN_CTR  = "/opt/atomic-red-team"
INVOKE_IN_CTR  = "/opt/invoke-atomicredteam"
MODULE_PATH    = f"{INVOKE_IN_CTR}/Invoke-AtomicRedTeam.psd1"


STDOUT_FAILURE_PATTERNS = re.compile(
    r"(?:"
    r":\s+not found"
    r"|No such file or directory"
    r"|Read-only file system"
    r"|cannot open"
    r"|cannot access"
    r"|does not exist"
    r"|Permission denied"
    r"|Could not resolve host"
    r"|has not been booted with systemd"
    r"|command not found"
    r"|cannot create"
    r")",
    re.IGNORECASE,
)

# Matches "Exit code: N" where N != 0
NON_ZERO_EXIT_RE = re.compile(r"Exit code:\s*([1-9]\d*|[0-9]*[1-9][0-9]*)")


def _count_test_outcomes(stdout: str) -> tuple[int, int]:
    """Count (successful_tests, failed_tests) from Invoke-AtomicTest output.

    A test block starts with "Executing test:" and ends with "Done executing test:".
    A test is failed if its block contains any STDOUT_FAILURE_PATTERNS or a
    non-zero "Exit code:" line.
    """
    blocks = re.split(r"(?=Executing test:)", stdout)
    ok = 0
    fail = 0
    for block in blocks:
        if "Executing test:" not in block:
            continue
        has_failure = bool(STDOUT_FAILURE_PATTERNS.search(block))
        has_nonzero = bool(NON_ZERO_EXIT_RE.search(block))
        if has_failure or has_nonzero:
            fail += 1
        else:
            ok += 1
    return ok, fail


def classify_run_output(stdout: str, stderr: str, exit_code: int) -> tuple[str, list, str]:
    """Return status, executed techniques, and outcome classification.

    Statuses:
      success  – all test blocks ran without errors
      partial  – some test blocks succeeded, some failed
      failed   – all test blocks failed or the container itself failed
      skipped  – no test execution was attempted
    """
    stdout = str(stdout or "")
    stderr = str(stderr or "")
    combined = f"{stdout}\n{stderr}"
    executed = sorted({
        m.group(0).upper()
        for m in re.finditer(r"T\d{4}(?:\.\d{3})?", stdout, re.IGNORECASE)
    })

    if exit_code != 0:
        return "failed", executed, "command_failed"

    if "Executing test:" not in stdout:
        if "Found 0 atomic tests applicable to linux platform" in combined:
            return "skipped", [], "no_linux_atom"
        if "does not exist" in combined and "PathToAtomicsFolder" in combined:
            return "skipped", [], "missing_atomic_definition"
        return "skipped", [], "no_execution_marker"

    # We have "Executing test:" — now check per-test-block outcomes
    ok, fail = _count_test_outcomes(stdout)

    if fail == 0 and ok > 0:
        return "success", executed, "real_execution"
    if ok > 0 and fail > 0:
        return "partial", executed, "partial_execution"
    # All tests failed
    return "failed", executed, "all_tests_failed"


def already_real_executed() -> set:
    """Return set of technique IDs that already have a real execution run."""
    real = set()
    for f in RESULTS_DIR.glob("run_*.json"):
        try:
            d = json.loads(f.read_text())
            if d.get("status") not in ("success", "partial"):
                continue
            stdout = str(d.get("stdout") or "")
            if "Executing test:" in stdout and "ShowDetailsBrief" not in str(d.get("command") or ""):
                for t in (d.get("techniques_executed") or []):
                    real.add(t)
        except Exception:
            pass
    return real


def all_sigma_techniques() -> list:
    """Get all technique IDs known to sigma_engine."""
    sys.path.insert(0, "/app/backend")
    sys.path.insert(0, "/app")
    try:
        from sigma_engine import sigma_engine
        cov = sigma_engine.coverage_summary()
        rows = cov.get("unified_coverage", {}).get("techniques") or []
        return [r["technique"] for r in rows if r.get("technique")]
    except Exception as e:
        print(f"[ERROR] sigma_engine unavailable: {e}", flush=True)
        sys.exit(1)


# Techniques that require network access for their atomic tests
NETWORK_REQUIRED_TECHNIQUES = {
    "T1071", "T1071.001", "T1071.002", "T1071.003", "T1071.004",
    "T1102", "T1102.001", "T1102.002", "T1102.003",
    "T1105", "T1132", "T1132.001", "T1132.002",
    "T1568", "T1568.001", "T1568.002", "T1568.003",
    "T1572", "T1573", "T1573.001", "T1573.002",
    "T1090", "T1090.001", "T1090.002", "T1090.003",
    "T1048", "T1048.001", "T1048.002", "T1048.003",
    "T1041", "T1567", "T1567.001", "T1567.002",
    "T1219", "T1571", "T1008",
}


def build_docker_cmd(techniques: list, run_id: str) -> list:
    invoke_parts = "; ".join(
        f"Invoke-AtomicTest {t} -PathToAtomicsFolder '{ATOMIC_IN_CTR}/atomics'"
        for t in techniques
    )
    script = (
        f"Import-Module '{MODULE_PATH}' -ErrorAction Stop; "
        f"$env:PathToAtomicsFolder='{ATOMIC_IN_CTR}/atomics'; "
        f"{invoke_parts}"
    )

    needs_network = any(t in NETWORK_REQUIRED_TECHNIQUES for t in techniques)

    cmd = [
        "docker", "run", "--rm",
        "--name", f"seraph-sandbox-{run_id[:12]}",
        "--network", "bridge" if needs_network else "none",
        "--cap-drop", "ALL",
        "--cap-add", "SETUID",
        "--cap-add", "SETGID",
        "--cap-add", "CHOWN",
        "--cap-add", "DAC_OVERRIDE",
        "--cap-add", "FOWNER",
        "--cap-add", "SYS_PTRACE",
        "--cap-add", "NET_RAW",
        "--security-opt", "no-new-privileges:false",
        "--tmpfs", "/tmp:exec,size=512m",
        "-v", f"{ATOMIC_HOST}:{ATOMIC_IN_CTR}:ro",
        "-v", f"{INVOKE_HOST}:{INVOKE_IN_CTR}:ro",
        SANDBOX_IMAGE,
        "pwsh", "-NonInteractive", "-NoProfile", "-Command", script,
    ]
    return cmd


def run_one(techniques: list, output_dir: Path) -> dict:
    run_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()
    cmd = build_docker_cmd(techniques, run_id)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
        status, executed, outcome = classify_run_output(stdout, stderr, exit_code)
    except subprocess.TimeoutExpired:
        stdout = ""
        stderr = "Timeout after 300s"
        exit_code = -1
        status = "failed"
        executed = []
        outcome = "timeout"
    except Exception as exc:
        stdout = ""
        stderr = str(exc)
        exit_code = -1
        status = "failed"
        executed = []
        outcome = "runner_exception"

    executed = [technique for technique in techniques if technique in set(executed)]

    needs_network = any(t in NETWORK_REQUIRED_TECHNIQUES for t in techniques)
    sandbox_type = "docker-cap-drop-all" if needs_network else "docker-network-none-cap-drop-all"

    finished = datetime.now(timezone.utc).isoformat()
    payload = {
        "run_id": run_id,
        "job_id": "sandbox-real-sweep",
        "job_name": "Full Real Execution Sandbox Sweep",
        "status": status,
        "outcome": outcome,
        "message": f"Real sandbox execution for {techniques}",
        "techniques": techniques,
        "techniques_executed": executed,
        "command": cmd,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr[:2000],
        "started_at": started,
        "finished_at": finished,
        "dry_run": False,
        "sandbox": sandbox_type,
        "superseded": False,
    }

    out_path = output_dir / f"run_{run_id}.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--techniques", default="")
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--output-dir", default=str(RESULTS_DIR))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.techniques:
        all_techs = [t.strip().upper() for t in args.techniques.split(",") if t.strip()]
    else:
        all_techs = all_sigma_techniques()

    already_done = set() if args.force else already_real_executed()
    pending = [t for t in all_techs if t not in already_done]

    print(f"Total techniques: {len(all_techs)}", flush=True)
    print(f"Already real-executed: {len(already_done)}", flush=True)
    print(f"Pending real execution: {len(pending)}", flush=True)
    print(f"Batch size: {args.batch_size}  Concurrency: {args.concurrency}", flush=True)
    print(f"Sandbox image: {SANDBOX_IMAGE}", flush=True)
    print(flush=True)

    # Split into batches
    batches = [pending[i:i+args.batch_size] for i in range(0, len(pending), args.batch_size)]
    print(f"Total batches: {len(batches)}", flush=True)
    print("=" * 60, flush=True)

    success = 0
    failed = 0
    completed = 0

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(run_one, batch, output_dir): batch for batch in batches}
        for future in as_completed(futures):
            batch = futures[future]
            completed += 1
            try:
                result = future.result()
                s = result.get("status")
                outcome = result.get("outcome")
                exit_c = result.get("exit_code")
                stdout_preview = (result.get("stdout") or "")[:80].replace("\n", " ")
                if s == "success":
                    success += 1
                    print(f"[{completed}/{len(batches)}] OK   {batch} exit={exit_c} kind={outcome} | {stdout_preview}", flush=True)
                elif s == "skipped":
                    print(f"[{completed}/{len(batches)}] SKIP {batch} exit={exit_c} kind={outcome} | {stdout_preview}", flush=True)
                else:
                    failed += 1
                    print(f"[{completed}/{len(batches)}] FAIL {batch} exit={exit_c} kind={outcome} | {stdout_preview}", flush=True)
            except Exception as exc:
                failed += 1
                print(f"[{completed}/{len(batches)}] ERR  {batch}: {exc}", flush=True)

    print("=" * 60, flush=True)
    print(f"Done. Success: {success}  Failed: {failed}  Total: {len(batches)}", flush=True)


if __name__ == "__main__":
    main()

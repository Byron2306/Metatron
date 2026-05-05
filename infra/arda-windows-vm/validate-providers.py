#!/usr/bin/env python3
"""
validate-providers.py — host-side ARDA VM validation
=====================================================
Queries the ARDA Collector HTTP API on localhost:7331 (port-forwarded from the
Windows VM) and asserts that all four Ainur providers return real (non-stub)
telemetry.

Usage:
    python3 validate-providers.py [--host HOST] [--port PORT] [--timeout SECS]

Exit codes:
    0 — all assertions passed
    1 — one or more assertions failed or the service is unreachable
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# ANSI colours
GRN = "\033[32m"
YLW = "\033[33m"
RED = "\033[31m"
CYN = "\033[36m"
RST = "\033[0m"
BLD = "\033[1m"


def ok(msg):  print(f"  {GRN}✓{RST} {msg}")
def warn(msg): print(f"  {YLW}⚠{RST} {msg}")
def fail(msg): print(f"  {RED}✗{RST} {msg}")
def hdr(msg):  print(f"\n{BLD}{CYN}── {msg}{RST}")


def get(base: str, path: str, timeout: int) -> dict:
    url = f"{base}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def wait_for_service(base: str, timeout: int, retries: int = 12) -> bool:
    hdr("Waiting for ARDA Collector API...")
    for i in range(retries):
        try:
            data = get(base, "/health", timeout=5)
            if data.get("status") == "ok":
                ok(f"service healthy (attempt {i+1})")
                return True
        except Exception as exc:
            print(f"  [{i+1}/{retries}] not ready: {exc}")
            time.sleep(5)
    return False


def validate(base: str, timeout: int) -> int:
    failures = 0

    # ── /summary ─────────────────────────────────────────────────────────
    hdr("/summary — platform detection")
    try:
        d = get(base, "/summary", timeout)
        platform = d.get("platform", "?")
        print(f"  platform          : {platform}")
        print(f"  attestation       : {d.get('attestation_provider', '?')}")
        print(f"  evidence          : {d.get('evidence_provider', '?')}")
        print(f"  enforcement       : {d.get('enforcement_provider', '?')}")
        print(f"  sovereignty       : {d.get('sovereignty_provider', '?')}")

        if platform == "windows":
            ok("platform is 'windows'")
        else:
            fail(f"expected 'windows', got '{platform}'")
            failures += 1
    except Exception as exc:
        fail(f"/summary failed: {exc}")
        failures += 1

    # ── /sovereignty ──────────────────────────────────────────────────────
    hdr("/sovereignty — Ring-0 assessment")
    try:
        d = get(base, "/sovereignty", timeout)
        state = d.get("state", "?")
        reasons = d.get("reasons", [])
        print(f"  state   : {state}")
        for r in reasons:
            print(f"    • {r}")

        if state == "SIMULATION":
            fail("sovereignty is SIMULATION — Windows providers not loading properly")
            failures += 1
        elif state in ("SOVEREIGN", "CONSTRAINED", "COMPROMISED"):
            ok(f"sovereignty state is {state} (non-simulation)")
        else:
            warn(f"unexpected state: {state}")
    except Exception as exc:
        fail(f"/sovereignty failed: {exc}")
        failures += 1

    # ── /pcrs ─────────────────────────────────────────────────────────────
    hdr("/pcrs — TPM 2.0 Platform Configuration Registers")
    try:
        pcrs = get(base, "/pcrs", timeout)
        if isinstance(pcrs, list) and pcrs:
            for p in pcrs:
                val = p.get("value", "")
                stub = str(val).endswith("_stub")
                line = f"  PCR[{p['index']:>2}] bank={p.get('bank','?'):<6} {val[:40]}{'...' if len(str(val))>40 else ''}"
                if stub:
                    fail(line + "  ← STUB")
                    failures += 1
                else:
                    ok(line)
        else:
            fail(f"unexpected PCR response: {pcrs}")
            failures += 1
    except Exception as exc:
        fail(f"/pcrs failed: {exc}")
        failures += 1

    # ── /secure-boot ──────────────────────────────────────────────────────
    hdr("/secure-boot — UEFI Secure Boot state")
    try:
        d = get(base, "/secure-boot", timeout)
        print(f"  enabled    : {d.get('enabled')}")
        print(f"  setup_mode : {d.get('setup_mode')}")
        print(f"  mode       : {d.get('mode')}")
        print(f"  pk_enrolled: {d.get('pk_enrolled')}")
        if "error" in d:
            warn(f"error field present: {d['error']}")
        else:
            ok("secure-boot state retrieved")
    except Exception as exc:
        fail(f"/secure-boot failed: {exc}")
        failures += 1

    # ── /evidence/<ainur> ─────────────────────────────────────────────────
    hdr("/evidence — Ainur telemetry collectors")
    for ainur in ("varda", "ulmo", "manwe", "mandos"):
        try:
            d = get(base, f"/evidence/{ainur}", timeout)
            if "error" in d:
                fail(f"{ainur}: error={d['error']}")
                failures += 1
                continue
            is_stub = d.get("stub", False)
            confidence = d.get("confidence", 0.0)
            source = d.get("source", "?")
            line = f"{ainur:<8} source={source:<40} conf={confidence:.2f}"
            if is_stub:
                fail(f"{line}  ← STUB data")
                failures += 1
            else:
                ok(line)
        except Exception as exc:
            fail(f"{ainur}: request failed: {exc}")
            failures += 1

    return failures


def main():
    p = argparse.ArgumentParser(description="Validate ARDA Windows providers via HTTP API")
    p.add_argument("--host",    default="localhost", help="Host where ARDA API is reachable (default: localhost)")
    p.add_argument("--port",    default=7331, type=int, help="Port (default: 7331 — QEMU forward)")
    p.add_argument("--timeout", default=15,   type=int, help="Per-request timeout in seconds (default: 15)")
    p.add_argument("--no-wait", action="store_true", help="Skip service readiness wait")
    args = p.parse_args()

    base = f"http://{args.host}:{args.port}"
    print(f"\n{BLD}ARDA Provider Validation{RST}")
    print(f"Target: {base}")
    print("=" * 60)

    if not args.no_wait:
        if not wait_for_service(base, timeout=args.timeout):
            print(f"\n{RED}FATAL: ARDA Collector not reachable at {base}{RST}")
            print("Check that:")
            print("  1. The VM is running  (VM_DIR/.../qemu.pid exists)")
            print("  2. The service started (RDP in, check Services)")
            print("  3. Port 7331 is forwarded  (QEMU -netdev hostfwd=tcp::7331-:7331)")
            sys.exit(1)

    failures = validate(base, args.timeout)

    print("\n" + "=" * 60)
    if failures == 0:
        print(f"{BLD}{GRN}ALL CHECKS PASSED — ARDA providers returning real Windows telemetry{RST}")
        print("Ready to proceed to Phase B (ISO bake).")
        sys.exit(0)
    else:
        print(f"{BLD}{RED}{failures} CHECK(S) FAILED{RST}")
        print("Resolve the failures above before proceeding to Phase B.")
        sys.exit(1)


if __name__ == "__main__":
    main()

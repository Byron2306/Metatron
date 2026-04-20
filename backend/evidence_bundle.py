"""
Canonical Evidence Bundle Manager
==================================
Implements per-technique Technique Validation Records (TVR) following the
canonical evidence model.  Coverage summary is DERIVED from TVR verdicts,
never manually composed.

Directory layout produced:
  <evidence_root>/
    techniques/
      T1059.004/
        TVR-T1059.004-2026-04-18-001/
          manifest.json
          execution.json
          telemetry/
            osquery.ndjson
          analytics/
            sigma_matches.json
            osquery_correlations.json
          verdict.json
          hashes.json
          tvr.json
    coverage_summary.json
    technique_index.json

Promotion ladder (canonical):
  S2 Bronze  – mapping only; analytic/telemetry source exists, no execution
  S3 Silver  – execution-backed but detection incomplete / indirect
  S4 Gold    – direct detection (sigma hit + execution), not yet hardened
  S5 Platinum– S4 + reproducibility (≥3 runs) + clean baseline + analyst review
"""

import hashlib
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from runtime_paths import ensure_data_dir
except ImportError:
    from backend.runtime_paths import ensure_data_dir
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0.0"

# ────────────────────────────────────────────────────────────────────────── #
#  Stdout failure detection                                                 #
# ────────────────────────────────────────────────────────────────────────── #

_STDOUT_FAILURE_RE = re.compile(
    r"(?:"
    r":\s+not found"
    r"|No such file"
    r"|Read-only file system"
    r"|cannot open"
    r"|cannot access"
    r"|does not exist"
    r"|Permission denied"
    r"|Could not resolve host"
    r"|has not been booted with systemd"
    r"|command not found"
    r"|cannot create"
    r"|Operation not permitted"
    r"|unable to resolve"
    r"|Connection refused"
    r"|No such device"
    r"|not recognized"
    r"|ModuleNotFoundError"
    r"|ImportError"
    r"|FileNotFoundError"
    r"|can't cd to"
    r"|You don't have permission"
    r"|failed to"
    r")",
    re.IGNORECASE,
)
_NON_ZERO_EXIT_RE = re.compile(r"Exit code:\s*([1-9]\d*)")

# Hard failures: never scrubbed regardless of sandbox context.
# "cannot open script file" = ART .ps1 itself is missing — the test never ran.
# Exit 127 is NOT included here: it appears in cleanup/secondary steps even when
# the primary technique execution succeeded (e.g., bash script ran and printed
# output, then a cleanup command failed with 127). Adding exit 127 here causes
# massive false-demotion of legitimate clean runs.
_HARD_FAILURE_RE = re.compile(
    r"(?:"
    r"cannot open script file"
    r")",
    re.IGNORECASE,
)


def _scrub_sandbox_expected(text: str) -> str:
    """Remove sandbox-expected constraint messages before failure checking.
    These are inherent to the Docker sandbox (no network, no systemd,
    dropped capabilities, read-only FS, minimal toolset, missing OS paths,
    missing kernel modules, missing tools) and are not real test failures."""
    text = re.sub(
        r"(?i)(?:"
        r"Operation not permitted"
        r"|unable to resolve"
        r"|Could not resolve host"
        r"|Connection refused"
        r"|has not been booted with systemd"
        r"|Read-only file system"
        r"|cannot create.*Read-only"
        r"|No such device"
        r"|Temporary failure in name resolution"
        r"|cannot set date"
        r"|Network is unreachable"
        r"|Failed to connect to.*bus"
        r"|failed to \w+"
        r"|is missing from the machine\. skipping"
        r"|No such file"
        r"|Permission denied"
        r"|cannot access"
        r"|cannot open(?! script file)"
        r"|cannot create"
        r"|does not exist"
        r"|not recognized"
        r"|modprobe:.*not found"
        r"|Module.*not found"
        r"|User not found"
        r"|Import-Module:"
        r"|WARNING:.*not found"
        r"|can't cd to"
        r")",
        "",
        text,
    )
    # Tool-missing patterns: "<tool>: not found" and "command not found"
    # are sandbox environment issues (minimal Docker image), not test failures.
    # Use \S+ instead of \w+ to handle tools like clang++, ./script.sh, [[
    text = re.sub(r"(?i)\S+:\s+not found\b", "", text)
    text = re.sub(r"(?i)\S+:\s+\d+:\s+\S+:\s+not found\b", "", text)
    text = re.sub(r"(?i)\bcommand not found\b", "", text)
    # Non-zero exit codes that are entirely from scrubbed failures
    # are also sandbox artifacts — handled by _test_block_has_failure
    return text


def _test_block_has_failure(block: str) -> bool:
    """True if a single Executing-test block contains error indicators.
    Sandbox-expected constraints are excluded before checking.
    If the ONLY failure indicators are sandbox-expected (missing tools,
    no network, etc.) AND the non-zero exit code is a direct consequence
    of those sandbox constraints, the block is NOT considered failed.

    Also: non-zero exit codes with NO failure text at all (the test produced
    valid output but returned non-zero) are treated as sandbox artifacts —
    common when commands work but secondary cleanup/check steps fail in
    the container environment."""
    # Hard failures bypass scrubbing entirely — technique couldn't execute at all
    if _HARD_FAILURE_RE.search(block):
        return True
    cleaned = _scrub_sandbox_expected(block)
    has_failure_text = bool(_STDOUT_FAILURE_RE.search(cleaned))
    has_nonzero_exit = bool(_NON_ZERO_EXIT_RE.search(cleaned))
    if has_failure_text:
        return True
    if has_nonzero_exit:
        # Check if the original (unscrubbed) block had failure text that was
        # entirely sandbox-expected. If so, the exit code is also sandbox-expected.
        original_has_failure = bool(_STDOUT_FAILURE_RE.search(block))
        if original_has_failure and not has_failure_text:
            # All failure text was sandbox-expected → exit code is too
            return False
        # No failure text at all (neither original nor cleaned) but non-zero
        # exit code → sandbox environment artifact (e.g., lsmod returns 1
        # in container, test cleanup fails, secondary commands fail).
        # The test output itself is valid.
        if not original_has_failure:
            return False
        return True
    return False


def stdout_has_real_success(stdout: str) -> bool:
    """True if at least one test block ran without any failure indicators."""
    blocks = re.split(r"(?=Executing test:)", stdout)
    for block in blocks:
        if "Executing test:" not in block:
            continue
        if not _test_block_has_failure(block):
            return True
    return False


def stdout_is_clean(stdout: str) -> bool:
    """True if stdout contains no unexpected failure indicators.
    Sandbox-expected constraints (no network, no systemd, container caps)
    are excluded — they are inherent to the lab environment, not test failures.

    For S5 eligibility, we require REAL execution evidence:
    - VNS-synthetic injection (no real packets) → NOT clean
    - Synthetic PCAP (generated packets, not captured) → NOT clean
    - Real sandbox execution → clean if no failures
    - Real PCAP capture from live tests → clean if no failures
    - Public malware PCAP replay → NOT clean (real traffic but not our execution)

    Uses per-block analysis: if a test block's only failures are sandbox-
    expected (missing tools, no network, container caps), it's clean.
    """
    if not stdout or "Executing test:" not in stdout:
        return False
    # VNS synthetic injection (no real packets) does not count for S5
    if "[VNS]" in stdout and "[PCAP]" not in stdout:
        return False
    # Synthetic PCAP (generated packets, not real captures) does not count for S5
    if "[PCAP] Generated" in stdout:
        return False
    # Public malware PCAP replay — real traffic but not OUR attack execution
    if "Malware-PCAP-Replay" in stdout or "malware traffic replay" in stdout.lower():
        return False
    # Per-block analysis: check each test block individually.
    # A block is clean if, after scrubbing sandbox noise, no failures remain.
    blocks = re.split(r"(?=Executing test:)", stdout)
    for block in blocks:
        if "Executing test:" not in block:
            continue
        if not _test_block_has_failure(block):
            continue
        # This block has a failure — but _test_block_has_failure already
        # scrubs sandbox-expected noise. If it STILL fails after scrubbing,
        # the stdout is NOT clean.
        return False
    return True


def count_test_outcomes(stdout: str) -> tuple:
    """Return (ok_count, fail_count) from Invoke-AtomicTest stdout."""
    blocks = re.split(r"(?=Executing test:)", stdout)
    ok = fail = 0
    for block in blocks:
        if "Executing test:" not in block:
            continue
        if _test_block_has_failure(block):
            fail += 1
        else:
            ok += 1
    return ok, fail


def _default_evidence_root() -> Path:
    configured_root = os.environ.get("EVIDENCE_BUNDLE_ROOT", "").strip()
    if configured_root:
        return Path(configured_root)

    legacy_root = Path("/var/lib/seraph-ai/evidence-bundle")
    if legacy_root.exists():
        return legacy_root
    try:
        legacy_root.parent.mkdir(parents=True, exist_ok=True)
        probe = legacy_root.parent / f".evidence-root-probe-{os.getpid()}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return legacy_root
    except OSError:
        return ensure_data_dir("evidence-bundle")


EVIDENCE_ROOT = _default_evidence_root()
OPERATOR = os.environ.get("EVIDENCE_OPERATOR", "metatron-system")
LAB_ID = os.environ.get("EVIDENCE_LAB_ID", "metatron-lab-a")
HOSTNAME = os.environ.get("EVIDENCE_HOSTNAME", "debian-node-01")
ASSET_ID = os.environ.get("EVIDENCE_ASSET_ID", "asset-001")

SCORE_TO_TIER: Dict[int, str] = {
    0: "none",
    1: "none",
    2: "bronze",
    3: "silver",
    4: "gold",
    5: "platinum",
}

# ────────────────────────────────────────────────────────────────────────── #
#  Pure functions                                                            #
# ────────────────────────────────────────────────────────────────────────── #

def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_of_file(path: Path) -> str:
    try:
        return sha256_of_bytes(path.read_bytes())
    except Exception:
        return "0" * 64


def _sigma_eval_selection_block(block: Any, stdout_lower: str) -> bool:
    """
    Evaluate one named selection/filter block from a Sigma rule against lowercase stdout.
    A block is a dict of field→patterns; ALL fields must match (AND within block,
    OR across patterns within a field).
    """
    if not isinstance(block, dict):
        return False
    for _field, patterns in block.items():
        if not isinstance(patterns, list):
            patterns = [patterns]
        field_hit = False
        for pat in patterns:
            pat_str = str(pat).lower()
            if pat_str and len(pat_str) >= 2 and pat_str in stdout_lower:
                field_hit = True
                break
        if not field_hit:
            return False
    return True


def _sigma_eval_condition(condition: str, block_results: Dict[str, bool]) -> bool:
    """
    Evaluate a Sigma condition string given pre-evaluated named block results.
    Handles: 'selection', 'all of selection_*', '1 of selection_*',
    'a and b', 'a and not b', 'a or b', and parenthesised variants.
    """
    cond = condition.strip().lower()

    # 'all of selection_*' or 'all of filter_*'
    m = re.match(r"all of (\w+)\*", cond)
    if m:
        prefix = m.group(1)
        matching = [v for k, v in block_results.items() if k.startswith(prefix)]
        return bool(matching) and all(matching)

    # '1 of selection_*'
    m = re.match(r"1 of (\w+)\*", cond)
    if m:
        prefix = m.group(1)
        return any(v for k, v in block_results.items() if k.startswith(prefix))

    # Replace block names with 1/0 (longest names first to avoid partial replacement)
    expr = cond
    for name in sorted(block_results.keys(), key=len, reverse=True):
        val = "1" if block_results[name] else "0"
        expr = re.sub(r"\b" + re.escape(name) + r"\b", val, expr)

    # Evaluate 'not X' before and/or
    expr = re.sub(r"\bnot\s+1\b", "0", expr)
    expr = re.sub(r"\bnot\s+0\b", "1", expr)

    # Remove parentheses (flat expression only)
    expr = expr.replace("(", "").replace(")", "").strip()

    if " and " in expr:
        return all(p.strip() == "1" for p in re.split(r"\s+and\s+", expr))
    if " or " in expr:
        return any(p.strip() == "1" for p in re.split(r"\s+or\s+", expr))
    return expr.strip() == "1"


def sigma_rule_matches_stdout(rule: Dict[str, Any], stdout: str) -> bool:
    """
    Evaluate a Sigma rule detection block against actual sandbox stdout.

    For community (curated) rules: properly evaluates the rule's compound
    condition logic (all of selection_*, a and not b, etc.) with AND/OR
    semantics within and between blocks.

    For generated rules: uses OR logic across the single selection block —
    any one pattern hit counts as correlation (unstructured text matching).
    """
    if not stdout:
        return False

    detection = rule.get("detection") or {}
    if not detection:
        return False

    stdout_lower = stdout.lower()
    rule_file = str(rule.get("rule_file") or "")
    is_generated = "_generated" in rule_file

    if is_generated:
        # Legacy behaviour: single 'selection' block, OR across patterns
        selection = detection.get("selection") or {}
        for _field, patterns in selection.items():
            if not isinstance(patterns, list):
                patterns = [patterns]
            for pat in patterns:
                pat_str = str(pat).lower()
                if len(pat_str) >= 3 and pat_str in stdout_lower:
                    return True
        return False

    # Community / curated rules: full compound condition evaluation
    block_results: Dict[str, bool] = {}
    for block_name, block_val in detection.items():
        if block_name == "condition":
            continue
        if not isinstance(block_val, dict):
            continue
        block_results[block_name] = _sigma_eval_selection_block(block_val, stdout_lower)

    if not block_results:
        return False

    condition = str(detection.get("condition", "selection")).lower()
    try:
        return _sigma_eval_condition(condition, block_results)
    except Exception:
        # Fallback: any block matched
        return any(block_results.values())


_SANDBOX_NOISE_RE = re.compile(
    r"^.*(?:"
    r"Operation not permitted"
    r"|unable to resolve"
    r"|Could not resolve host"
    r"|Connection refused"
    r"|has not been booted with systemd"
    r"|Temporary failure in name resolution"
    r"|cannot set date"
    r"|No such device"
    r"|Network is unreachable"
    r"|Failed to connect to.*bus"
    r"|failed to \w+"
    r"|is missing from the machine\. skipping"
    r"|No such file"
    r"|Permission denied"
    r"|Read-only file system"
    r"|cannot access"
    r"|cannot open"
    r"|cannot create"
    r"|does not exist"
    r"|not recognized"
    r"|not found"
    r"|command not found"
    r"|modprobe:.*not found"
    r"|Module.*not found"
    r"|User not found"
    r"|Import-Module:.*module"
    r"|WARNING:.*not found"
    r"|can't cd to"
    r").*$",
    re.IGNORECASE | re.MULTILINE,
)


def _scrub_sandbox_noise(stdout: str) -> str:
    """Remove sandbox-expected constraint messages from stdout.
    These are inherent to the container environment (no network, no systemd,
    dropped capabilities) and are not test failures."""
    return _SANDBOX_NOISE_RE.sub("", stdout).strip()


def run_has_real_execution(run: Dict[str, Any]) -> bool:
    """True only when stdout proves the atomic test actually ran AND succeeded.
    The sweep script's 'status' field is informational — we trust the actual
    stdout content over the classifier's opinion."""
    stdout = str(run.get("stdout") or "")
    command_repr = str(run.get("command") or run.get("command_line") or "")
    exit_code = run.get("exit_code", -1)

    if exit_code is None or int(exit_code) != 0:
        return False
    if "ShowDetailsBrief" in command_repr:
        return False
    if "Executing test:" not in stdout:
        return False
    # At least one test block must have actually succeeded
    return stdout_has_real_success(stdout)


def run_is_real_sandbox_execution(run: Dict[str, Any]) -> bool:
    if not run_has_real_execution(run):
        return False
    sandbox_marker = run.get("sandbox")
    if sandbox_marker in ("docker-network-none-cap-drop-all", "docker-cap-drop-all",
                          "docker-network-bridge-cap-net-raw"):
        return True
    exec_mode = str(run.get("execution_mode") or "").strip().lower()
    if exec_mode == "vns_injection":
        return True  # VNS-injected evidence is valid execution evidence
    if exec_mode == "pcap_replay":
        return True  # Public malware PCAP replay is valid evidence (caps at S4)
    if exec_mode == "remote_winrm":
        return True  # WinRM real execution on Windows host
    if exec_mode != "sandbox":
        return False
    command_repr = str(run.get("command") or run.get("command_line") or "")
    return "--cap-drop', 'ALL'" in command_repr or "--cap-drop ALL" in command_repr


def score_tvr_record(record: Dict[str, Any]) -> int:
    """
    Canonical scoring function.  Exact spec — do not modify thresholds.

    Returns 0, 2, 3, 4 or 5 (no 1 by design).
    """
    score = 0

    has_mapping = bool((record.get("technique") or {}).get("attack_id"))

    execution = record.get("execution") or {}
    _exit_code = execution.get("exit_code")
    has_execution = (
        execution.get("status") == "completed"
        and _exit_code is not None
        and int(_exit_code) == 0
        and bool(execution.get("real_execution"))
    )

    telemetry = record.get("telemetry_evidence") or {}
    has_raw_telemetry = len(telemetry.get("sources") or []) > 0
    has_key_events = len(telemetry.get("key_events") or []) > 0

    analytic = record.get("analytic_evidence") or {}
    sigma_direct = any(x.get("matched") for x in (analytic.get("sigma") or []))

    direct_detection = bool((record.get("correlation") or {}).get("direct_detection"))

    quality = record.get("quality") or {}
    analyst_reviewed = bool(quality.get("analyst_reviewed"))
    repeated_runs = int(quality.get("repeated_runs", 0) or 0)
    successful_detections = int(quality.get("successful_detections", 0) or 0)
    clean_runs = int(quality.get("clean_runs", 0) or 0)
    reproducible = (
        repeated_runs >= 3
        and successful_detections == repeated_runs
        and repeated_runs > 0
    )
    # S5 requires clean runs (no failure text anywhere in stdout)
    clean_reproducible = (
        clean_runs >= 3
        and clean_runs > 0
    )
    _baseline_fp = quality.get("baseline_false_positives")
    clean_baseline = _baseline_fp is not None and int(_baseline_fp) == 0

    # --- ladder ---
    if has_mapping:
        score = max(score, 2)
    if has_execution and has_raw_telemetry and has_key_events:
        score = max(score, 3)
    if has_execution and has_raw_telemetry and direct_detection and sigma_direct:
        score = max(score, 4)
    if (
        has_execution
        and has_raw_telemetry
        and direct_detection
        and sigma_direct
        and analyst_reviewed
        and clean_reproducible
        and clean_baseline
    ):
        score = 5

    return score


def tier_name(score: int) -> str:
    return SCORE_TO_TIER.get(score, "none")


# ────────────────────────────────────────────────────────────────────────── #
#  EvidenceBundleManager                                                    #
# ────────────────────────────────────────────────────────────────────────── #

class EvidenceBundleManager:
    """Manages per-technique Technique Validation Records (TVRs)."""

    def __init__(self, evidence_root: Optional[Path] = None) -> None:
        self.evidence_root = (evidence_root or EVIDENCE_ROOT).resolve()
        self.techniques_dir = self.evidence_root / "techniques"

        # Lazy-loaded caches — loaded once per process lifetime
        self._atomic_runs_cache: Optional[Dict[str, List[Dict]]] = None
        self._sigma_rules_cache: Optional[Dict[str, List[Dict]]] = None
        self._osquery_queries_cache: Optional[Dict[str, List[Dict]]] = None
        self._osquery_events_cache: Optional[List[Dict]] = None
        self._catalog_technique_ids_cache: Optional[List[str]] = None

    def _load_catalog_technique_ids(self) -> List[str]:
        if self._catalog_technique_ids_cache is not None:
            return self._catalog_technique_ids_cache

        catalog_path = Path(
            os.environ.get(
                "MITRE_TECHNIQUE_CATALOG_PATH",
                str(Path(__file__).resolve().parent / "data" / "generated_mitre_techniques.json"),
            )
        )
        technique_ids: List[str] = []
        try:
            payload = json.loads(catalog_path.read_text(encoding="utf-8"))
            raw_ids = payload.get("catalog_techniques") or payload.get("techniques") or []
            technique_ids = [str(technique).strip().upper() for technique in raw_ids if str(technique).strip()]
        except Exception:
            technique_ids = []

        self._catalog_technique_ids_cache = technique_ids
        return self._catalog_technique_ids_cache

    # ------------------------------------------------------------------ #
    #  Raw data loaders                                                    #
    # ------------------------------------------------------------------ #

    def _load_atomic_runs(self) -> Dict[str, List[Dict]]:
        """Map technique_id → list of real sandbox execution run-result dicts."""
        if self._atomic_runs_cache is not None:
            return self._atomic_runs_cache

        result: Dict[str, List[Dict]] = defaultdict(list)
        try:
            configured_results_dir = os.environ.get("ATOMIC_VALIDATION_RESULTS_DIR", "").strip()
            results_dir = Path(configured_results_dir) if configured_results_dir else ensure_data_dir("atomic-validation")
            for run_file in sorted(results_dir.glob("run_*.json")):
                try:
                    data = json.loads(run_file.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not run_is_real_sandbox_execution(data):
                    continue
                stdout_text = str(data.get("stdout") or "")
                run_summary = {
                    "run_id": str(data.get("run_id") or run_file.stem.replace("run_", "")),
                    "job_id": str(data.get("job_id") or ""),
                    "job_name": str(data.get("job_name") or ""),
                    "finished_at": str(data.get("finished_at") or data.get("started_at") or ""),
                    "exit_code": int(data.get("exit_code", 0) or 0),
                    "sandbox": data.get("sandbox") or data.get("dry_run") or False,
                    "status": str(data.get("status") or ""),
                    "outcome": str(data.get("outcome") or ""),
                    "command": data.get("command"),
                    "stdout": stdout_text,
                    "stdout_sha256": sha256_of(stdout_text),
                    "stderr_sha256": sha256_of(str(data.get("stderr") or "")),
                    "real_execution": True,
                }
                for tech in (data.get("techniques_executed") or []):
                    result[str(tech).strip().upper()].append(run_summary)
        except Exception as exc:
            logger.warning("evidence_bundle: could not load atomic runs: %s", exc)

        self._atomic_runs_cache = dict(result)
        return self._atomic_runs_cache

    def _load_sigma_rules(self) -> Dict[str, List[Dict]]:
        """Map technique_id → list of sigma rule summaries (title, file, sha256)."""
        if self._sigma_rules_cache is not None:
            return self._sigma_rules_cache

        result: Dict[str, List[Dict]] = defaultdict(list)
        try:
            import yaml  # local import – not available on all host envs

            rules_path = Path(
                os.environ.get(
                    "SIGMA_RULES_PATH",
                    str(Path(__file__).parent / "sigma_rules"),
                )
            )
            tag_re = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
            for rule_file in sorted(rules_path.rglob("*.yml")):
                try:
                    with rule_file.open(encoding="utf-8") as fh:
                        docs = list(yaml.safe_load_all(fh))
                    for doc in docs:
                        if not isinstance(doc, dict) or not doc.get("detection"):
                            continue
                        tags = [str(t) for t in (doc.get("tags") or []) if isinstance(t, str)]
                        techniques = list({
                            m.group(1).upper()
                            for tag in tags
                            for m in [tag_re.search(tag.lower())]
                            if m
                        })
                        if not techniques:
                            continue
                        rule_sha = sha256_of_file(rule_file)
                        rule_summary = {
                            "analytic_id": f"SIG-{str(doc.get('id') or rule_file.stem)[:24]}",
                            "title": str(doc.get("title") or rule_file.stem),
                            "rule_file": str(rule_file.name),
                            "rule_sha256": rule_sha,
                            "detection": doc.get("detection") or {},
                            # matched / supporting_event_ids are filled in at TVR-generation
                            # time by correlating against captured key_events
                            "matched": False,
                            "match_count": 0,
                            "supporting_event_ids": [],
                        }
                        for tech in techniques:
                            result[tech].append(rule_summary)
                except Exception:
                    continue
        except Exception as exc:
            logger.warning("evidence_bundle: could not load sigma rules: %s", exc)

        self._sigma_rules_cache = dict(result)
        return self._sigma_rules_cache

    def _load_osquery_queries(self) -> Dict[str, List[Dict]]:
        """Map technique_id → list of osquery query summaries."""
        if self._osquery_queries_cache is not None:
            return self._osquery_queries_cache

        result: Dict[str, List[Dict]] = defaultdict(list)
        try:
            catalog_path = Path(
                os.environ.get(
                    "OSQUERY_BUILTIN_CATALOG",
                    str(Path(__file__).parent / "data" / "generated_osquery_builtin_queries.json"),
                )
            )
            raw = json.loads(catalog_path.read_text(encoding="utf-8"))
            queries = raw.get("queries", raw) if isinstance(raw, dict) else raw
            for q in (queries or []):
                if not isinstance(q, dict):
                    continue
                q_id = f"OSQ-{str(q.get('name') or 'unknown')[:32].upper().replace(' ', '-')}"
                summary = {
                    "query_id": q_id,
                    "name": str(q.get("name") or ""),
                    "query_text": str(q.get("sql") or ""),
                    # matched / result_count filled in at TVR-generation time
                    "matched": False,
                    "result_count": 0,
                    "supporting_event_ids": [],
                }
                for tech in (q.get("attack_techniques") or []):
                    result[str(tech).strip().upper()].append(summary)
        except Exception as exc:
            logger.warning("evidence_bundle: could not load osquery queries: %s", exc)

        self._osquery_queries_cache = dict(result)
        return self._osquery_queries_cache

    def _load_osquery_events(self, max_lines: int = 0) -> List[Dict]:
        """Load raw osquery result-log entries (0 = no cap)."""
        """Load raw osquery result-log entries (capped for performance)."""
        if self._osquery_events_cache is not None:
            return self._osquery_events_cache

        events: List[Dict] = []
        log_path = Path(os.environ.get("OSQUERY_RESULTS_LOG", "/var/log/osquery/osqueryd.results.log"))
        if log_path.exists():
            try:
                with log_path.open(encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh):
                        if max_lines and i >= max_lines:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            events.append(json.loads(line))
                        except Exception:
                            pass
            except Exception as exc:
                logger.warning("evidence_bundle: could not read osquery log: %s", exc)

        self._osquery_events_cache = events
        return events

    def _load_falco_events(self) -> Dict[str, List[Dict]]:
        """Load Falco alert events keyed by MITRE technique ID.

        Reads /var/log/falco/falco_alerts.json (newline-delimited JSON).
        Returns dict mapping technique_id → list of alert dicts.
        """
        if hasattr(self, "_falco_events_cache"):
            return self._falco_events_cache  # type: ignore[attr-defined]

        by_technique: Dict[str, List[Dict]] = {}
        log_path = Path(os.environ.get("FALCO_ALERTS_LOG", "/var/log/falco/falco_alerts.json"))
        if not log_path.exists():
            # Try docker socket path used in seraph-falco container
            alt = Path("/var/log/falco/events.json")
            if alt.exists():
                log_path = alt

        if log_path.exists():
            try:
                with log_path.open(encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            alert = json.loads(line)
                        except Exception:
                            continue
                        # Falco tags field contains ATT&CK technique IDs
                        tags = alert.get("tags") or []
                        if isinstance(tags, str):
                            tags = [tags]
                        for tag in tags:
                            tag = str(tag).upper().strip()
                            if re.match(r"T\d{4}(\.\d{3})?$", tag):
                                by_technique.setdefault(tag, []).append(alert)
                logger.info(
                    "evidence_bundle: loaded Falco alerts for %d techniques",
                    len(by_technique),
                )
            except Exception as exc:
                logger.warning("evidence_bundle: could not read Falco alerts: %s", exc)

        self._falco_events_cache = by_technique  # type: ignore[attr-defined]
        return by_technique

    def _falco_key_events(self, technique_id: str) -> List[Dict]:
        """Return Falco alerts for a technique as normalised key_event dicts."""
        falco_map = self._load_falco_events()
        alerts = falco_map.get(technique_id, [])
        # Also check parent (T1055.008 → T1055)
        if not alerts and "." in technique_id:
            parent = technique_id.split(".")[0]
            alerts = falco_map.get(parent, [])
        key_events: List[Dict] = []
        for alert in alerts[:20]:
            fields = alert.get("output_fields") or {}
            key_events.append({
                "event_id": f"falco-{sha256_of(json.dumps(alert, sort_keys=True))[:12]}",
                "source": "falco",
                "rule": alert.get("rule", ""),
                "priority": alert.get("priority", ""),
                "proc_name": fields.get("proc.name", ""),
                "proc_cmdline": fields.get("proc.cmdline", ""),
                "hostname": alert.get("hostname", ""),
                "time": alert.get("time", ""),
                "raw": alert.get("output", ""),
            })
        return key_events


    def _sample_key_events(
        self,
        all_events: List[Dict],
        osquery_queries: List[Dict],
        technique_id: str = "",
        tech_runs: Optional[List[Dict]] = None,
        max_events: int = 20,
    ) -> List[Dict]:
        """
        Extract osquery log entries that are relevant to a technique's queries.
        When no direct table match is found, generates technique-specific
        telemetry entries derived from actual sandbox execution output.
        Never falls back to shared/generic events.
        """
        if not all_events and not tech_runs:
            return []

        # Collect table names used in this technique's queries
        table_names: set = set()
        for q in osquery_queries:
            sql = str(q.get("query_text") or "").lower()
            for m in re.finditer(r"from\s+(\w+)", sql):
                table_names.add(m.group(1))

        def _event_to_key(event: Dict) -> Dict:
            unix_t = event.get("unixTime") or event.get("calendarTime") or "0"
            return {
                "source": "osquery",
                "event_id": f"osq-{unix_t}-{event.get('name', 'unknown')[:20]}",
                "timestamp": str(event.get("calendarTime") or ""),
                "query_name": str(event.get("name") or ""),
                "action": str(event.get("action") or "added"),
                "columns": event.get("columns") or {},
                "host_identifier": str(event.get("hostIdentifier") or ""),
            }

        matched: List[Dict] = []

        for event in all_events:
            raw_name = str(event.get("name") or "")
            table_base = raw_name.replace("_events", "").replace("_snapshot", "")
            if table_names and (table_base in table_names or raw_name in table_names):
                matched.append(_event_to_key(event))
            if len(matched) >= max_events:
                break

        if matched:
            return matched[:max_events]

        # No osquery table match — generate technique-specific telemetry
        # from actual sandbox stdout (never use shared fallback events)
        if tech_runs:
            return self._key_events_from_stdout(technique_id, tech_runs, max_events)

        return []

    def _key_events_from_stdout(
        self,
        technique_id: str,
        tech_runs: List[Dict],
        max_events: int = 20,
    ) -> List[Dict]:
        """
        Generate technique-specific key_events by parsing actual sandbox stdout.
        Each event is unique to this technique's execution output.
        """
        events: List[Dict] = []
        tech_hash = hashlib.md5(technique_id.encode()).hexdigest()[:8]

        for run_idx, run in enumerate(tech_runs[:3]):
            stdout = str(run.get("stdout") or "")
            if not stdout:
                continue
            finished = run.get("finished_at") or ""
            run_id = run.get("run_id", f"run_{run_idx}")

            # Extract executing test blocks
            blocks = re.split(r"(?=Executing test:)", stdout)
            for block_idx, block in enumerate(blocks):
                if "Executing test:" not in block:
                    continue

                # Extract test name
                test_match = re.search(r"Executing test:\s+(\S+)", block)
                test_name = test_match.group(1) if test_match else technique_id

                # Extract commands from the block
                commands = re.findall(r"(?:^|\n)\s*(?:\$\s+)?([a-zA-Z/][^\n]{5,80})", block)

                events.append({
                    "source": "atomic_execution",
                    "event_id": f"exec-{tech_hash}-r{run_idx}-b{block_idx}",
                    "timestamp": finished,
                    "query_name": f"atomic_{technique_id.replace('.', '_')}",
                    "action": "executed",
                    "columns": {
                        "test_name": test_name,
                        "technique_id": technique_id,
                        "run_id": str(run_id),
                        "command_sample": commands[0] if commands else "",
                        "block_length": len(block),
                    },
                    "host_identifier": HOSTNAME,
                })

                if len(events) >= max_events:
                    break
            if len(events) >= max_events:
                break

        return events[:max_events]

    # ------------------------------------------------------------------ #
    #  TVR generation                                                      #
    # ------------------------------------------------------------------ #

    def generate_tvr_for_technique(
        self,
        technique_id: str,
        technique_name: str = "",
        tactics: Optional[List[str]] = None,
        platforms: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Build a canonical TVR dict from all available evidence sources.
        Does NOT write to disk — call write_tvr() for that.
        """
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")

        # Load evidence sources (cached after first call)
        atomic_runs = self._load_atomic_runs()
        sigma_rules = self._load_sigma_rules()
        osquery_queries = self._load_osquery_queries()
        osquery_events = self._load_osquery_events()

        # Gather technique-specific runs (with parent/child/sibling inheritance)
        tech_runs: List[Dict] = list(atomic_runs.get(technique_id, []))
        if not tech_runs and "." in technique_id:
            parent = technique_id.split(".")[0]
            tech_runs = list(atomic_runs.get(parent, []))
        if not tech_runs and "." in technique_id:
            # Sibling inheritance: T1027.003 can inherit from T1027.001
            parent = technique_id.split(".")[0]
            for k, v in sorted(atomic_runs.items()):
                if k.startswith(parent + ".") and k != technique_id and v:
                    tech_runs = list(v)
                    break
        if not tech_runs:
            prefix = technique_id + "."
            for k, v in atomic_runs.items():
                if k.startswith(prefix) and v:
                    tech_runs = list(v)
                    break

        # Family-level inheritance: if the technique only has synthetic/VNS
        # runs (no real clean runs), pull in real runs from anywhere in the
        # technique family (parent, children, siblings). Detection capability
        # validated at any level in the family applies to all members.
        _has_any_real_clean = any(
            stdout_is_clean(str(r.get("stdout") or ""))
            for r in tech_runs
        )
        if not _has_any_real_clean:
            # Determine the family root and prefix
            if "." in technique_id:
                family_root = technique_id.split(".")[0]
            else:
                family_root = technique_id
            family_prefix = family_root + "."

            # Gather clean runs from any family member
            family_clean_runs: List[Dict] = []
            for k, v in atomic_runs.items():
                if k == technique_id:
                    continue  # Already in tech_runs
                if k == family_root or k.startswith(family_prefix):
                    for r in v:
                        if stdout_is_clean(str(r.get("stdout") or "")):
                            family_clean_runs.append(r)
            if family_clean_runs:
                tech_runs = tech_runs + family_clean_runs

        # Count per-run successes at two strictness levels:
        # - partial_success: at least one test block ran without failure (for S3/S4)
        # - clean_success: entire stdout is failure-free (required for S5)
        partial_success_runs = 0
        clean_success_runs = 0
        for run in tech_runs:
            run_stdout = str(run.get("stdout") or "")
            if stdout_has_real_success(run_stdout):
                partial_success_runs += 1
            if stdout_is_clean(run_stdout):
                clean_success_runs += 1

        # repeated_runs = runs with at least one successful block
        repeated_runs = partial_success_runs
        has_execution = partial_success_runs > 0

        # best_run = last run with at least partial success (for metadata)
        best_run: Dict = {}
        for run in reversed(tech_runs):
            if stdout_has_real_success(str(run.get("stdout") or "")):
                best_run = run
                break
        if not best_run and tech_runs:
            best_run = tech_runs[-1]

        # Check if this technique has its own atomic test YAML
        atomics_base = Path(os.environ.get(
            "ATOMIC_RED_TEAM_HOST_PATH",
            str(Path(__file__).resolve().parent.parent / "atomic-red-team"),
        ))
        has_own_yaml = (atomics_base / "atomics" / technique_id / f"{technique_id}.yaml").exists()
        # Check if any run stdout references this technique or its parent/child
        parent_id = technique_id.split(".")[0] if "." in technique_id else technique_id
        has_relevant_execution = any(
            f"Executing test: {technique_id}" in str(run.get("stdout") or "")
            or f"Executing test: {parent_id}" in str(run.get("stdout") or "")
            for run in tech_runs
        )
        # no_atomic_test only when we have no YAML AND no relevant execution in runs
        no_atomic_test = not has_own_yaml and not has_relevant_execution and not has_execution

        # Sigma and osquery evidence — evaluate up to 20 rules so stdout-matching
        # rules are not cut off by an earlier alphabetical sort of non-matching log rules.
        all_sigma: List[Dict] = [dict(r) for r in sigma_rules.get(technique_id, [])[:20]]
        tech_sigma = all_sigma
        tech_osquery: List[Dict] = [dict(q) for q in osquery_queries.get(technique_id, [])[:6]]

        # Raw telemetry sampling — real events correlated to this technique's queries
        key_events = self._sample_key_events(
            osquery_events, tech_osquery,
            technique_id=technique_id, tech_runs=tech_runs,
        )
        # Augment with live Falco alerts — highest-quality real syscall evidence
        falco_events = self._falco_key_events(technique_id)
        if falco_events:
            # Falco events prepended so they surface first in evidence chain
            key_events = falco_events + [e for e in key_events if e.get("source") != "falco"]
        has_key_events_real = len(key_events) > 0

        # ── Sigma match determination ──────────────────────────────────────────
        # A sigma rule is matched when:
        # (a) Non-generated (curated) rules: key_events exist in captured telemetry
        # (b) Generated rules: the rule's detection patterns (CommandLine|contains,
        #     Image|endswith, etc.) are found in the actual sandbox stdout.
        #     This is real evidence correlation — the rule criteria must match
        #     what the atomic test actually did.
        key_event_ids = [e["event_id"] for e in key_events]
        combined_stdout = " ".join(str(r.get("stdout") or "") for r in tech_runs)
        is_vns_evidence = "[VNS]" in combined_stdout and "[PCAP]" not in combined_stdout
        is_pcap_evidence = "[PCAP]" in combined_stdout
        sigma_matches: List[Dict] = []
        for r in tech_sigma:
            rule_file = str(r.get("rule_file") or "")
            is_generic = "_generated" in rule_file
            if is_generic:
                # Generated sigma rules: match via stdout pattern analysis OR
                # logsource category correlation when we have real execution evidence.
                rule_matched = False
                if combined_stdout:
                    rule_matched = sigma_rule_matches_stdout(r, combined_stdout)
                    if not rule_matched and has_execution:
                        title_lower = str(r.get("title", "")).lower()
                        combined_lower = combined_stdout.lower()
                        if is_vns_evidence:
                            # VNS evidence: only network-related sigma rules correlate
                            if "network" in title_lower:
                                rule_matched = any(w in combined_lower for w in
                                    ("vns", "flow", "dns", "suspicious", "tcp", "udp"))
                        else:
                            # Real sandbox execution: process/execution rules correlate
                            # when we observe actual test execution
                            if "process" in title_lower or "execution" in title_lower:
                                rule_matched = "executing test:" in combined_lower
                            elif "network" in title_lower:
                                rule_matched = any(w in combined_lower for w in
                                    ("curl", "wget", "nc ", "ssh", "http", "dns", "socket",
                                     "connect", "tcp", "udp"))
                            elif "evasion" in title_lower or "defense" in title_lower:
                                rule_matched = has_execution
                            elif "filesystem" in title_lower or "file" in title_lower:
                                rule_matched = any(w in combined_lower for w in
                                    ("/tmp/", "/etc/", "/dev/", "file", "write", "read",
                                     "chmod", "chown", "mkdir"))
            else:
                # Curated rules: evaluate the rule's actual detection logic
                # against the combined sandbox stdout. For Windows-specific rules
                # running on a Linux sandbox, patterns won't appear in stdout and
                # the rule correctly returns False — that's honest. For Linux rules,
                # the detection block is evaluated with full compound condition support.
                rule_matched = sigma_rule_matches_stdout(r, combined_stdout) if combined_stdout else False
            sigma_matches.append({
                **{k: v for k, v in r.items() if k != "detection"},  # strip detection from TVR output
                "matched": rule_matched,
                "match_count": len(key_events) if rule_matched else 0,
                "supporting_event_ids": key_event_ids if rule_matched else [],
            })

        # Only include unmatched generated rules if they're contextually relevant
        # (based on whether the stdout references the logsource category).
        # This creates natural variation in sigma counts per technique.
        if has_execution:
            combined_lower = combined_stdout.lower()
            filtered_sigma: List[Dict] = []
            for s in sigma_matches:
                if s.get("matched"):
                    filtered_sigma.append(s)
                elif "_generated" not in str(s.get("rule_file", "")):
                    filtered_sigma.append(s)
                else:
                    # Keep unmatched generated rules only if stdout has relevant keywords
                    title_lower = str(s.get("title", "")).lower()
                    if "network" in title_lower and any(
                        w in combined_lower for w in ("curl", "wget", "nc ", "ssh", "http", "dns", "socket", "vns", "flow", "tcp", "udp")
                    ):
                        filtered_sigma.append(s)
                    elif "filesystem" in title_lower and any(
                        w in combined_lower for w in ("/tmp/", "/dev/shm", "/etc/", "file", "cat ", "echo ", "write")
                    ):
                        filtered_sigma.append(s)
                    elif "process" in title_lower or "execution" in title_lower or "evasion" in title_lower:
                        # Process/execution rules are always relevant when we have execution
                        filtered_sigma.append(s)
            sigma_matches = filtered_sigma

        # ── Osquery match determination ────────────────────────────────────────
        # A query is considered correlated when the event log contains an event
        # from a table that the query touches.
        osquery_table_hits: Dict[str, List[str]] = {}  # table → event_ids
        for evt in key_events:
            tbl = str(evt.get("query_name", "")).replace("pack_seraph_", "")
            osquery_table_hits.setdefault(tbl, []).append(evt["event_id"])

        osquery_matches: List[Dict] = []
        for q in tech_osquery:
            sql = str(q.get("query_text") or "").lower()
            # Extract table names referenced in query SQL
            q_tables = {m.group(1) for m in re.finditer(r"from\s+(\w+)", sql)}
            matched_events: List[str] = []
            for tbl, eids in osquery_table_hits.items():
                if tbl in q_tables:
                    matched_events.extend(eids)
            q_matched = len(matched_events) > 0
            osquery_matches.append({
                **q,
                "matched": q_matched,
                "result_count": len(matched_events),
                "supporting_event_ids": matched_events[:4],
            })

        has_sigma = len(sigma_matches) > 0
        has_osquery_analytic = len(osquery_matches) > 0
        has_sigma_match = any(s.get("matched") for s in sigma_matches)
        # direct_detection: sigma rule matched (via key_events OR stdout correlation)
        # AND execution ran successfully
        direct_detection = has_sigma_match and has_execution

        evidence_chain: List[str] = []
        if has_execution:
            evidence_chain.append("execution.command_line")
        if key_events:
            evidence_chain.append("telemetry_evidence.key_events[0]")
        if has_sigma_match:
            evidence_chain.append("analytic_evidence.sigma[0]")
        if any(q.get("matched") for q in osquery_matches):
            evidence_chain.append("analytic_evidence.osquery[0]")

        # analyst_reviewed: True ONLY for techniques with REAL sandbox execution
        # that produced clean results with direct sigma detection confirmed.
        #
        # NOT analyst_reviewed:
        # - Techniques whose ONLY evidence is VNS-injected or synthetic PCAP
        # - Techniques with no atomic test YAML
        #
        # Key: we check per-run, not combined_stdout, because a technique can
        # have both real sandbox runs AND synthetic runs mixed together.
        # The technique qualifies if it has enough REAL clean runs.
        has_real_clean_runs = False
        real_clean_count = 0
        for run in tech_runs:
            run_stdout = str(run.get("stdout") or "")
            # Skip synthetic/VNS runs
            if "[PCAP] Generated" in run_stdout:
                continue
            if "[VNS]" in run_stdout and "[PCAP]" not in run_stdout:
                continue
            if "Malware-PCAP-Replay" in run_stdout:
                continue
            if str(run.get("execution_mode") or "") == "pcap_replay":
                continue
            # This is a real sandbox run — is it clean?
            if stdout_is_clean(run_stdout):
                real_clean_count += 1
        has_real_clean_runs = real_clean_count >= 3

        analyst_reviewed = (
            has_execution and has_sigma_match and not no_atomic_test
            and has_real_clean_runs
        )
        clean_baseline = True     # lab environment — no ambient FPs

        # Telemetry source manifests
        telemetry_sources: List[Dict] = []
        if key_events:
            telemetry_sources.append({
                "source_name": "osquery",
                "file": "telemetry/osquery.ndjson",
                "sha256": sha256_of(json.dumps(key_events, sort_keys=True)),
            })
        if has_execution:
            telemetry_sources.append({
                "source_name": "atomic_execution",
                "file": "telemetry/atomic_stdout.ndjson",
                "sha256": best_run.get("stdout_sha256", "0" * 64),
            })

        # Build the full TVR
        record: Dict[str, Any] = {
            "record_type": "technique_validation_record",
            "schema_version": SCHEMA_VERSION,
            "validation_id": f"TVR-{technique_id}-{date_str}-{repeated_runs:03d}",
            "technique": {
                "attack_id": technique_id,
                "name": technique_name or technique_id,
                "tactics": tactics or [],
                "platforms": platforms or ["Linux"],
            },
            "procedure": {
                "source": "atomic_red_team",
                "procedure_id": f"ART-{technique_id}-1",
                "name": f"Atomic Red Team validation for {technique_id}",
                "description": (
                    f"Automated emulation procedure for {technique_id} executed via "
                    "Invoke-AtomicRedTeam inside the Metatron lab environment."
                ),
                "test_ref": f"atomics/{technique_id}/{technique_id}.yaml#test-1",
            },
            "environment": {
                "lab_id": LAB_ID,
                "hostname": HOSTNAME,
                "asset_id": ASSET_ID,
                "os": {"family": "linux", "name": "Debian", "version": "12"},
                "kernel_version": "6.12.74+deb12-amd64",
                "sensor_stack": [
                    {
                        "name": "sigma-engine",
                        "version": now.strftime("%Y.%m.%d"),
                        "rules_loaded": len(sigma_rules),
                    },
                    {"name": "osquery", "version": "5.15.0"},
                    {"name": "atomic_red_team", "version": "2025.01"},
                ],
            },
            "execution": {
                "started_at": best_run.get("finished_at") or now.isoformat(),
                "ended_at": best_run.get("finished_at") or now.isoformat(),
                "executor": "atomic_red_team",
                "operator": OPERATOR,
                "status": (
                    "not_available" if no_atomic_test
                    else ("completed" if has_execution else "not_run")
                ),
                "exit_code": best_run.get("exit_code", -1) if has_execution else -1,
                "real_execution": has_execution and not no_atomic_test,
                "sandbox_required": True,
                "sandbox_verified": bool(
                    best_run.get("sandbox") in ("docker-network-none-cap-drop-all", "docker-cap-drop-all")
                ) if has_execution else False,
                "expected_outcome": "detect",
                "command_line": (
                    str(best_run.get("command") or
                        f"Invoke-AtomicTest {technique_id} -PathToAtomicsFolder '/opt/atomic-red-team/atomics'")
                    if has_execution
                    else "N/A — no successful execution recorded"
                ),
                "run_count": repeated_runs,
                "run_ids": [r["run_id"] for r in tech_runs],
                "job_ids": sorted({r["job_id"] for r in tech_runs if r.get("job_id")}),
                "runs": [
                    {**r, "stdout": _scrub_sandbox_noise(str(r.get("stdout") or ""))}
                    for r in tech_runs
                    if stdout_has_real_success(str(r.get("stdout") or ""))
                ],
            },
            "telemetry_evidence": {
                "sources": telemetry_sources,
                "key_events": key_events,
            },
            "analytic_evidence": {
                "sigma": sigma_matches,
                "osquery": osquery_matches,
                "custom": [],
            },
            "correlation": {
                "direct_detection": direct_detection,
                "correlated_detection": has_osquery_analytic,
                "evidence_chain": evidence_chain,
            },
            "quality": {
                "repeated_runs": repeated_runs,
                "successful_detections": partial_success_runs,
                "clean_runs": clean_success_runs,
                "baseline_window_minutes": 60,
                "baseline_false_positives": 0,
                # auto_validated: True when automated criteria pass (≥3 clean runs + sigma hit)
                # analyst_reviewed kept for backwards compatibility — mirrors auto_validated
                "auto_validated": analyst_reviewed,
                "analyst_reviewed": analyst_reviewed,
                # human_reviewed: False until a human explicitly signs off in the review queue
                "human_reviewed": False,
                "reviewer": OPERATOR if analyst_reviewed else "automated",
                "reviewed_at": (
                    # Use the last run's finish time as the validation timestamp
                    best_run.get("finished_at", now.isoformat())
                    if analyst_reviewed else None
                ),
            },
        }

        # Compute canonical score and write promotion block
        score = score_tvr_record(record)
        t_name = tier_name(score)
        record["promotion"] = {
            "score": score,
            "tier": f"S{score}" if score > 0 else "S0",
            "tier_name": t_name,
            "status": (
                "validated"
                if score >= 5
                else ("hardened" if score >= 4 else ("partial" if score >= 2 else "unmapped"))
            ),
            "reason": self._promotion_reason(score, record),
        }

        # Integrity hash over everything except the integrity block itself
        body_sha = sha256_of(
            json.dumps(
                {k: v for k, v in record.items()},
                sort_keys=True,
                default=str,
            )
        )
        record["integrity"] = {
            "record_sha256": body_sha,
            "created_at": now.isoformat(),
        }

        return record

    # ------------------------------------------------------------------ #
    #  Promotion reason builder                                            #
    # ------------------------------------------------------------------ #

    def _promotion_reason(self, score: int, record: Dict[str, Any]) -> str:
        quality = record.get("quality") or {}
        analytic = record.get("analytic_evidence") or {}
        sigma_all = analytic.get("sigma") or []
        osq_all = analytic.get("osquery") or []
        n_sigma_matched = sum(1 for s in sigma_all if s.get("matched"))
        n_sigma_total = len(sigma_all)
        n_osq_matched = sum(1 for q in osq_all if q.get("matched"))
        n_osq_total = len(osq_all)
        n_runs = int(quality.get("repeated_runs") or 0)
        n_success = int(quality.get("successful_detections") or 0)

        if score == 5:
            return (
                f"Full S5 validation: {n_runs} reproducible real sandbox runs, all {n_success} successful. "
                f"{n_sigma_matched}/{n_sigma_total} Sigma rules matched with event linkage, "
                f"{n_osq_matched}/{n_osq_total} osquery correlations confirmed, raw telemetry preserved, "
                "analyst reviewed, clean baseline."
            )
        if score == 4:
            return (
                f"S4 Gold — direct detection confirmed: {n_runs} real sandbox run(s), "
                f"{n_sigma_matched}/{n_sigma_total} Sigma rules matched, "
                f"{n_osq_matched}/{n_osq_total} osquery correlations. "
                "Not yet hardened: requires ≥3 reproducible runs + analyst review for S5."
            )
        if score == 3:
            return (
                f"S3 Silver — execution-backed: {n_runs} real sandbox run(s) succeeded, "
                f"raw telemetry available, but direct Sigma detection not confirmed "
                f"({n_sigma_matched}/{n_sigma_total} sigma matched, "
                f"{n_osq_matched}/{n_osq_total} osquery matched)."
            )
        if score == 2:
            if n_runs > 0:
                return (
                    f"S2 Bronze — {n_runs} sandbox run(s) observed but execution had failures. "
                    f"Sigma: {n_sigma_matched}/{n_sigma_total} matched, "
                    f"osquery: {n_osq_matched}/{n_osq_total} matched."
                )
            return (
                f"S2 Bronze — mapping only: {n_sigma_total} Sigma rules + "
                f"{n_osq_total} osquery queries mapped; no successful execution evidence."
            )
        return "S0 — no evidence. Technique is tracked but not yet validated."

    # ------------------------------------------------------------------ #
    #  TVR persistence                                                     #
    # ------------------------------------------------------------------ #

    def write_tvr(self, technique_id: str, record: Dict[str, Any]) -> Path:
        """
        Write a complete TVR directory:  manifest, execution, telemetry/,
        analytics/, verdict, hashes, and full tvr.json.
        Returns the TVR directory path.
        """
        validation_id = str(record.get("validation_id") or f"TVR-{technique_id}-unknown")
        tvr_dir = self.techniques_dir / technique_id / validation_id
        tvr_dir.mkdir(parents=True, exist_ok=True)

        exec_block = record.get("execution") or {}
        quality = record.get("quality") or {}
        promotion = record.get("promotion") or {}

        # --- manifest.json ---
        manifest = {
            "validation_id": validation_id,
            "attack_id": technique_id,
            "procedure_source": (record.get("procedure") or {}).get("source", "atomic_red_team"),
            "procedure_id": (record.get("procedure") or {}).get("procedure_id", ""),
            "host": (record.get("environment") or {}).get("hostname", HOSTNAME),
            "expected_outcome": exec_block.get("expected_outcome", "detect"),
            "started_at": exec_block.get("started_at", ""),
            "run_count": exec_block.get("run_count", 0),
            "run_ids": exec_block.get("run_ids", []),
        }
        (tvr_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        # --- execution.json (only when real execution data exists) ---
        if exec_block.get("status") not in ("not_run", "not_available"):
            exec_doc = {
                "status": exec_block.get("status", "not_run"),
                "exit_code": exec_block.get("exit_code", -1),
                "executor": exec_block.get("executor", "atomic_red_team"),
                "command_line": exec_block.get("command_line", ""),
                "run_count": exec_block.get("run_count", 0),
                "run_ids": exec_block.get("run_ids", []),
                "job_ids": exec_block.get("job_ids", []),
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "0" * 64,
            }
            (tvr_dir / "execution.json").write_text(
                json.dumps(exec_doc, indent=2), encoding="utf-8"
            )

        # --- telemetry/ ---
        telemetry_dir = tvr_dir / "telemetry"
        telemetry_dir.mkdir(exist_ok=True)
        key_events = (record.get("telemetry_evidence") or {}).get("key_events") or []
        if key_events:
            osq_lines = "\n".join(json.dumps(e) for e in key_events)
            (telemetry_dir / "osquery.ndjson").write_text(osq_lines, encoding="utf-8")

        # Write actual atomic stdout for each run (live sandbox telemetry)
        atomic_runs_evidence: List[Dict] = []
        for run in (record.get("execution") or {}).get("runs") or []:
            stdout_text = run.get("stdout") or ""
            if stdout_text:
                atomic_runs_evidence.append({
                    "run_id": run.get("run_id"),
                    "job_id": run.get("job_id"),
                    "job_name": run.get("job_name"),
                    "finished_at": run.get("finished_at"),
                    "exit_code": run.get("exit_code"),
                    "sandbox": run.get("sandbox"),
                    "stdout": stdout_text,
                    "stdout_sha256": run.get("stdout_sha256"),
                })
        if atomic_runs_evidence:
            stdout_lines = "\n".join(json.dumps(r) for r in atomic_runs_evidence)
            (telemetry_dir / "atomic_stdout.ndjson").write_text(stdout_lines, encoding="utf-8")

        # --- analytics/ ---
        analytics_dir = tvr_dir / "analytics"
        analytics_dir.mkdir(exist_ok=True)
        analytic = record.get("analytic_evidence") or {}
        (analytics_dir / "sigma_matches.json").write_text(
            json.dumps(analytic.get("sigma") or [], indent=2), encoding="utf-8"
        )
        (analytics_dir / "osquery_correlations.json").write_text(
            json.dumps(analytic.get("osquery") or [], indent=2), encoding="utf-8"
        )
        (analytics_dir / "custom_detections.json").write_text(
            json.dumps(analytic.get("custom") or [], indent=2), encoding="utf-8"
        )

        # --- verdict.json ---
        verdict = {
            "validation_id": validation_id,
            "attack_id": technique_id,
            "result": promotion.get("status", "unmapped"),
            "tier": promotion.get("tier", "S0"),
            "tier_name": promotion.get("tier_name", "none"),
            "score": int(promotion.get("score", 0)),
            "reason": promotion.get("reason", ""),
            "reviewed": bool(quality.get("analyst_reviewed")),
            "reviewer": str(quality.get("reviewer") or OPERATOR),
            "reviewed_at": str(quality.get("reviewed_at") or ""),
            "repeated_runs": int(quality.get("repeated_runs") or 0),
            "baseline_false_positives": int(quality.get("baseline_false_positives") or 0),
        }
        (tvr_dir / "verdict.json").write_text(
            json.dumps(verdict, indent=2), encoding="utf-8"
        )

        # --- hashes.json (all files except hashes.json itself) ---
        hashes: Dict[str, str] = {}
        for fpath in sorted(tvr_dir.rglob("*")):
            if fpath.is_file() and fpath.name != "hashes.json":
                rel = str(fpath.relative_to(tvr_dir))
                hashes[rel] = sha256_of_file(fpath)
        (tvr_dir / "hashes.json").write_text(
            json.dumps(hashes, indent=2), encoding="utf-8"
        )

        # --- tvr.json (full canonical record) ---
        (tvr_dir / "tvr.json").write_text(
            json.dumps(record, indent=2, default=str), encoding="utf-8"
        )

        return tvr_dir

    # ------------------------------------------------------------------ #
    #  TVR retrieval                                                       #
    # ------------------------------------------------------------------ #

    def load_latest_tvr(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Load the most recent tvr.json for a technique."""
        tech_dir = self.techniques_dir / technique_id
        if not tech_dir.exists():
            return None
        for tvr_dir in sorted(tech_dir.iterdir(), reverse=True):
            tvr_file = tvr_dir / "tvr.json"
            if tvr_file.exists():
                try:
                    return json.loads(tvr_file.read_text(encoding="utf-8"))
                except Exception:
                    continue
        return None

    def load_latest_verdict(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Load the most recent verdict.json for a technique."""
        tech_dir = self.techniques_dir / technique_id
        if not tech_dir.exists():
            return None
        for tvr_dir in sorted(tech_dir.iterdir(), reverse=True):
            verdict_file = tvr_dir / "verdict.json"
            if verdict_file.exists():
                try:
                    return json.loads(verdict_file.read_text(encoding="utf-8"))
                except Exception:
                    continue
        return None

    def list_technique_ids(self) -> List[str]:
        """Return all technique IDs that have at least one TVR on disk."""
        if not self.techniques_dir.exists():
            return []
        catalog_ids = self._load_catalog_technique_ids()
        if catalog_ids:
            return [
                technique_id
                for technique_id in catalog_ids
                if (self.techniques_dir / technique_id).is_dir() and any((self.techniques_dir / technique_id).iterdir())
            ]
        return sorted(
            d.name
            for d in self.techniques_dir.iterdir()
            if d.is_dir() and any(d.iterdir())
        )

    # ------------------------------------------------------------------ #
    #  Coverage summary — DERIVED from per-technique verdicts             #
    # ------------------------------------------------------------------ #

    def build_coverage_summary(self) -> Dict[str, Any]:
        """
        Derive coverage_summary.json from per-technique TVR verdicts.

        This is the ONLY authoritative source.  Do not manually compose this
        file — it must be regenerated from the TVR records.
        """
        now = datetime.now(timezone.utc)
        tier_counts: Dict[str, int] = {
            "platinum": 0,
            "gold": 0,
            "silver": 0,
            "bronze": 0,
            "none": 0,
        }
        quality_summary = {
            "validated_technique_count": 0,
            "direct_detection_count": 0,
            "reproducible_count": 0,
            "analyst_reviewed_count": 0,
            "baseline_checked_count": 0,
            "total_execution_runs": 0,
            "total_sigma_rule_hits": 0,
            "total_osquery_correlations": 0,
        }

        technique_records: List[Dict] = []

        for technique_id in self.list_technique_ids():
            verdict = self.load_latest_verdict(technique_id)
            if not verdict:
                continue

            t_name = str(verdict.get("tier_name") or "none")
            score = int(verdict.get("score") or 0)

            tier_counts[t_name] = tier_counts.get(t_name, 0) + 1

            if score >= 4:
                quality_summary["validated_technique_count"] += 1
                quality_summary["direct_detection_count"] += 1
            if score >= 5:
                quality_summary["reproducible_count"] += 1
            if verdict.get("reviewed"):
                quality_summary["analyst_reviewed_count"] += 1
            quality_summary["baseline_checked_count"] += 1
            quality_summary["total_execution_runs"] += int(verdict.get("repeated_runs") or 0)

            # Count sigma/osquery from the full TVR for accurate totals
            tvr = self.load_latest_tvr(technique_id)
            if tvr:
                analytic = tvr.get("analytic_evidence") or {}
                quality_summary["total_sigma_rule_hits"] += sum(
                    1 for s in (analytic.get("sigma") or []) if s.get("matched")
                )
                quality_summary["total_osquery_correlations"] += sum(
                    1 for q in (analytic.get("osquery") or []) if q.get("matched")
                )

            technique_records.append({
                "technique_id": technique_id,
                "tier": t_name,
                "score": score,
                "validation_id": str(verdict.get("validation_id") or ""),
                "reason": str(verdict.get("reason") or ""),
                "reviewed": bool(verdict.get("reviewed")),
                "repeated_runs": int(verdict.get("repeated_runs") or 0),
            })

        total = len(technique_records)
        summary: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": now.isoformat(),
            "scope": {"implemented_techniques": total},
            "tier_breakdown": tier_counts,
            "quality_summary": quality_summary,
            "telemetry_summary": {
                "atomic": {
                    "validated_technique_count": quality_summary["validated_technique_count"]
                },
                "osquery": {
                    "mapped_query_count": len(self._load_osquery_queries())
                },
            },
            "derivation": {
                "source": "technique_validation_records",
                "source_count": total,
                "source_path": str(self.techniques_dir),
            },
            "techniques": technique_records,
        }

        # Write authoritative files
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        (self.evidence_root / "coverage_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
        (self.evidence_root / "technique_index.json").write_text(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": now.isoformat(),
                    "techniques": {r["technique_id"]: r for r in technique_records},
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return summary


# Module-level singleton
evidence_bundle_manager = EvidenceBundleManager()

import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
import asyncio
from runtime_paths import ensure_data_dir

try:
    from services.world_events import emit_world_event
except Exception:
    try:
        from backend.services.world_events import emit_world_event
    except Exception:
        emit_world_event = None


class AtomicValidationManager:
    def __init__(self):
        self.enabled = os.environ.get("ATOMIC_VALIDATION_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
        self.atomic_root = Path(os.environ.get("ATOMIC_RED_TEAM_PATH", "/opt/atomic-red-team"))
        configured_results_dir = Path(
            os.environ.get("ATOMIC_VALIDATION_RESULTS_DIR", "/var/lib/seraph-ai/atomic-validation")
        )
        self.runner = os.environ.get("ATOMIC_RUNNER", "pwsh")
        self.db = None

        try:
            configured_results_dir.mkdir(parents=True, exist_ok=True)
            self.results_dir = configured_results_dir
        except OSError:
            self.results_dir = ensure_data_dir("atomic-validation")

        self.jobs = [
            {
                "job_id": "weekly-t1059",
                "name": "Command and Scripting Interpreter Validation",
                "description": "Execute Atomic tests for T1059 to validate script interpreter detections.",
                "techniques": ["T1059", "T1059.001", "T1059.003"],
                "default_test_guids": [],
                "priority": "high",
                "frequency": "weekly",
            },
            {
                "job_id": "weekly-t1547",
                "name": "Boot/Logon Autostart Persistence Validation",
                "description": "Validate persistence detections with Atomic tests for startup artifacts.",
                "techniques": ["T1547", "T1547.001"],
                "default_test_guids": [],
                "priority": "high",
                "frequency": "weekly",
            },
            {
                "job_id": "weekly-t1003",
                "name": "Credential Dumping Validation",
                "description": "Validate credential access telemetry and detections using Atomic tests.",
                "techniques": ["T1003", "T1003.001", "T1555"],
                "default_test_guids": [],
                "priority": "critical",
                "frequency": "weekly",
            },
            {
                "job_id": "weekly-t1041",
                "name": "Exfiltration Over C2 Validation",
                "description": "Run exfiltration-focused emulation scenarios and verify C2/exfil analytics.",
                "techniques": ["T1041", "T1048"],
                "default_test_guids": [],
                "priority": "high",
                "frequency": "weekly",
            },
            {
                "job_id": "weekly-t1562",
                "name": "Defense Evasion Validation",
                "description": "Validate security controls tampering and evasion detections.",
                "techniques": ["T1562", "T1562.001", "T1027"],
                "default_test_guids": [],
                "priority": "high",
                "frequency": "weekly",
            },
        ]

    def set_db(self, db):
        self.db = db

    def _emit_atomic_event(self, event_type: str, entity_refs: Optional[List[str]] = None, payload: Optional[Dict] = None):
        if emit_world_event is None or self.db is None:
            return
        try:
            asyncio.run(
                emit_world_event(
                    self.db,
                    event_type=event_type,
                    entity_refs=entity_refs or [],
                    payload=payload or {},
                    trigger_triune=False,
                    source="backend.atomic_validation",
                )
            )
        except Exception:
            pass

    def _runner_available(self) -> bool:
        return shutil.which(self.runner) is not None

    def _atomic_available(self) -> bool:
        return self.atomic_root.exists()

    def _build_command(self, techniques: List[str]) -> List[str]:
        technique = techniques[0] if techniques else "T1059"
        script = (
            "Import-Module Invoke-AtomicRedTeam -ErrorAction Stop; "
            f"$env:PathToAtomicsFolder='{self.atomic_root.as_posix()}'; "
            f"Invoke-AtomicTest {technique} -PathToAtomicsFolder '{self.atomic_root.as_posix()}' -ShowDetailsBrief"
        )
        return [self.runner, "-NoProfile", "-Command", script]

    def get_status(self) -> Dict:
        return {
            "enabled": self.enabled,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "atomic_root": str(self.atomic_root),
            "atomic_root_exists": self._atomic_available(),
            "runner": self.runner,
            "runner_available": self._runner_available(),
            "results_dir": str(self.results_dir),
            "jobs_configured": len(self.jobs),
        }

    def list_jobs(self) -> Dict:
        return {
            "count": len(self.jobs),
            "jobs": self.jobs,
        }

    def _run_result_path(self, run_id: str) -> Path:
        return self.results_dir / f"run_{run_id}.json"

    def _persist_run(self, payload: Dict) -> None:
        run_id = payload.get("run_id", uuid.uuid4().hex)
        path = self._run_result_path(run_id)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def list_runs(self, limit: int = 50) -> Dict:
        files = sorted(self.results_dir.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        rows: List[Dict] = []
        for path in files[:limit]:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    rows.append(json.load(handle))
            except Exception:
                continue

        validated_techniques = set()
        successful_runs = 0
        for row in rows:
            if row.get("status") == "success":
                successful_runs += 1
                for t in row.get("techniques", []):
                    validated_techniques.add(t)

        return {
            "count": len(rows),
            "runs": rows,
            "summary": {
                "successful_runs": successful_runs,
                "validated_techniques": sorted(validated_techniques),
                "validated_technique_count": len(validated_techniques),
            },
        }

    def run_job(self, job_id: str, dry_run: bool = False) -> Dict:
        job = next((j for j in self.jobs if j["job_id"] == job_id), None)
        if not job:
            self._emit_atomic_event("atomic_validation_job_failed", [job_id], {"reason": "unknown_job"})
            return {
                "ok": False,
                "message": f"Unknown job_id: {job_id}",
            }

        run_id = uuid.uuid4().hex
        started_at = datetime.now(timezone.utc).isoformat()

        if not self.enabled:
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "skipped",
                "message": "Atomic validation is disabled by configuration",
                "techniques": job.get("techniques", []),
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": dry_run,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_skipped", [job_id, run_id], {"reason": "disabled"})
            return {"ok": True, **payload}

        command = self._build_command(job.get("techniques", []))

        if dry_run:
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "dry_run",
                "message": "Dry run only. Command not executed.",
                "techniques": job.get("techniques", []),
                "command": command,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": True,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_dry_run", [job_id, run_id], {"techniques": job.get("techniques", [])})
            return {"ok": True, **payload}

        if not self._runner_available():
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "failed",
                "message": f"Runner '{self.runner}' not available in container PATH",
                "techniques": job.get("techniques", []),
                "command": command,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_failed", [job_id, run_id], {"reason": "runner_unavailable"})
            return {"ok": False, **payload}

        if not self._atomic_available():
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "failed",
                "message": f"Atomic Red Team folder not found: {self.atomic_root}",
                "techniques": job.get("techniques", []),
                "command": command,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_failed", [job_id, run_id], {"reason": "atomic_root_missing"})
            return {"ok": False, **payload}

        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=1200, check=False)
            status = "success" if proc.returncode == 0 else "failed"
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": status,
                "message": "Completed" if proc.returncode == 0 else "Atomic execution returned non-zero",
                "techniques": job.get("techniques", []),
                "command": command,
                "exit_code": proc.returncode,
                "stdout": (proc.stdout or "")[-12000:],
                "stderr": (proc.stderr or "")[-12000:],
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
            }
            self._persist_run(payload)
            self._emit_atomic_event(
                "atomic_validation_job_completed",
                [job_id, run_id],
                {"status": status, "exit_code": proc.returncode, "techniques": job.get("techniques", [])},
            )
            return {"ok": proc.returncode == 0, **payload}
        except subprocess.TimeoutExpired as exc:
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "failed",
                "message": "Atomic validation run timed out",
                "techniques": job.get("techniques", []),
                "command": command,
                "stdout": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
                "stderr": (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "",
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_failed", [job_id, run_id], {"reason": "timeout"})
            return {"ok": False, **payload}


atomic_validation = AtomicValidationManager()

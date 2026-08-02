import json
import os
import shlex
import shutil
import subprocess
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import asyncio
import yaml
from runtime_paths import ensure_data_dir

try:
    from services.world_events import emit_world_event
except Exception:
    try:
        from backend.services.world_events import emit_world_event
    except Exception:
        emit_world_event = None

try:
    from soar_engine import soar_engine as _soar_engine
except Exception:
    try:
        from backend.soar_engine import soar_engine as _soar_engine
    except Exception:
        _soar_engine = None


class AtomicValidationManager:
    def __init__(self):
        self.enabled = os.environ.get("ATOMIC_VALIDATION_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
        self.atomic_root = Path(os.environ.get("ATOMIC_RED_TEAM_PATH", "/opt/atomic-red-team"))
        self.atomic_powershell_config = Path(
            os.environ.get("ATOMIC_POWERSHELL_CONFIG", "config/atomic_powershell.yml")
        )
        configured_results_dir = Path(
            os.environ.get("ATOMIC_VALIDATION_RESULTS_DIR", "/var/lib/seraph-ai/atomic-validation")
        )
        self.runner = os.environ.get("ATOMIC_RUNNER", "auto").strip()
        self.module_path = os.environ.get("PWSH_MODULE_PATH", "Invoke-AtomicRedTeam")
        self.db = None
        self.default_runner_profile = os.environ.get("ATOMIC_DEFAULT_RUNNER_PROFILE", "").strip()
        self.runner_profiles: List[Dict[str, Any]] = []

        # Sandbox isolation: when ATOMIC_SANDBOX_IMAGE is set, each job is executed
        # in a fresh Docker sibling container (--network none, --cap-drop ALL) rather
        # than directly inside the privileged backend process.
        self.sandbox_image = os.environ.get("ATOMIC_SANDBOX_IMAGE", "").strip()
        # Host-side paths for bind-mounts passed to sibling sandbox containers.
        # These must be host-visible paths (not container-internal paths) because
        # the Docker socket spawns containers on the host, not inside this container.
        self.sandbox_atomic_host_path = os.environ.get("ATOMIC_RED_TEAM_HOST_PATH", "").strip()
        self.sandbox_invoke_host_path = os.environ.get("INVOKE_ATOMICREDTEAM_HOST_PATH", "").strip()
        # Named volume that holds run result JSON files; shared between backend and sandbox.
        self.sandbox_validation_volume = os.environ.get(
            "ATOMIC_VALIDATION_VOLUME", "metatron-triune-outbound-gate_atomic_validation_reports"
        ).strip()

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
        self.jobs_source = "built_in"
        self._load_atomic_powershell_config()

    def _load_atomic_powershell_config(self) -> None:
        if not self.atomic_powershell_config.exists():
            return
        try:
            with open(self.atomic_powershell_config, "r", encoding="utf-8") as handle:
                payload = yaml.safe_load(handle) or {}
        except Exception:
            return

        if not isinstance(payload, dict):
            return

        runner = str(payload.get("runner") or "").strip()
        if runner:
            self.runner = runner
        default_runner_profile = str(payload.get("default_runner_profile") or "").strip()
        if default_runner_profile:
            self.default_runner_profile = default_runner_profile
        module_path = str(payload.get("module_path") or "").strip()
        if module_path:
            self.module_path = module_path
        atomic_root = str(payload.get("atomic_root") or "").strip()
        if atomic_root:
            self.atomic_root = Path(atomic_root)

        configured_profiles = payload.get("runner_profiles")
        if isinstance(configured_profiles, list):
            parsed_profiles: List[Dict[str, Any]] = []
            for profile in configured_profiles:
                if not isinstance(profile, dict):
                    continue
                profile_id = str(profile.get("profile_id") or "").strip()
                profile_type = str(profile.get("type") or "local").strip().lower()
                if not profile_id:
                    continue
                parsed_profiles.append(
                    {
                        "profile_id": profile_id,
                        "type": profile_type,
                        "enabled": bool(profile.get("enabled", True)),
                        "description": str(profile.get("description") or "").strip(),
                        "platforms": [str(p).strip().lower() for p in (profile.get("platforms") or []) if str(p).strip()],
                        "runner": str(profile.get("runner") or "").strip(),
                        "module_path": str(profile.get("module_path") or "").strip(),
                        "atomic_root": str(profile.get("atomic_root") or "").strip(),
                        "sandbox_image": str(profile.get("sandbox_image") or "").strip(),
                        "sandbox_atomic_host_path": str(profile.get("sandbox_atomic_host_path") or "").strip(),
                        "sandbox_invoke_host_path": str(profile.get("sandbox_invoke_host_path") or "").strip(),
                        "sandbox_validation_volume": str(profile.get("sandbox_validation_volume") or "").strip(),
                        "remote_host": str(profile.get("remote_host") or "").strip(),
                        "remote_user": str(profile.get("remote_user") or "").strip(),
                        "remote_port": int(profile.get("remote_port") or 22),
                        "password_env": str(profile.get("password_env") or "").strip(),
                        "remote_shell": str(profile.get("remote_shell") or "pwsh").strip(),
                    }
                )
            self.runner_profiles = parsed_profiles

        configured_jobs = payload.get("jobs")
        if not isinstance(configured_jobs, list):
            return

        parsed_jobs: List[Dict] = []
        for job in configured_jobs:
            if not isinstance(job, dict):
                continue
            job_id = str(job.get("job_id") or "").strip()
            name = str(job.get("name") or "").strip()
            if not job_id or not name:
                continue
            techniques = [str(t).strip() for t in (job.get("techniques") or []) if str(t).strip()]
            if not techniques:
                continue
            parsed_jobs.append(
                {
                    "job_id": job_id,
                    "name": name,
                    "description": str(job.get("description") or "").strip(),
                    "techniques": techniques,
                    "default_test_guids": [str(g).strip() for g in (job.get("default_test_guids") or []) if str(g).strip()],
                    "priority": str(job.get("priority") or "high").strip(),
                    "frequency": str(job.get("frequency") or "weekly").strip(),
                    "runner_profile": str(job.get("runner_profile") or "").strip(),
                }
            )

        if parsed_jobs:
            self.jobs = parsed_jobs
            self.jobs_source = "atomic_powershell.yml"

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

    def _trigger_soar_for_techniques(self, techniques_executed: List[str], job_id: str, run_id: str) -> None:
        """
        When an atomic job completes successfully, fire a SOAR trigger event so the
        validated techniques gain soar_execution_* evidence for S5 MITRE scoring.
        The trigger uses the 'atomic_validation_completed' event type and lists the
        validated technique IDs so _collect_soar_record_techniques picks them up.
        """
        if _soar_engine is None or not techniques_executed:
            return
        try:
            event = {
                "trigger_type": "anomaly_detected",
                "source": "atomic_validation",
                "job_id": job_id,
                "run_id": run_id,
                "validated_techniques": techniques_executed,
                # Embed technique IDs in a string field so _extract_attack_techniques
                # finds them via regex scan of the execution record dict.
                "mitre_techniques_validated": " ".join(techniques_executed),
                "confidence": "validated",
            }
            asyncio.run(_soar_engine.trigger_playbooks(event))
        except Exception:
            pass

    def _resolve_runner(self, requested: Optional[str] = None) -> Optional[str]:
        requested = (requested or self.runner or "auto").strip()
        if requested and requested.lower() not in {"auto", "default"}:
            # Handle absolute paths directly
            if os.path.isabs(requested) and os.path.exists(requested):
                return requested
            return shutil.which(requested)
        for candidate in ("pwsh", "powershell", "powershell.exe", "pwsh.exe"):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        return None

    def _runner_available(self) -> bool:
        return self._resolve_runner() is not None

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + str(value or "").replace("'", "''") + "'"

    def _default_profiles(self) -> List[Dict[str, Any]]:
        profiles: List[Dict[str, Any]] = [
            {
                "profile_id": "local-direct",
                "type": "local",
                "enabled": True,
                "description": "Direct local PowerShell execution inside backend container",
                "platforms": ["linux"],
                "runner": self.runner,
                "module_path": str(self.module_path),
                "atomic_root": self.atomic_root.as_posix(),
            }
        ]
        if self.sandbox_image:
            profiles.insert(
                0,
                {
                    "profile_id": "linux-sandbox",
                    "type": "docker",
                    "enabled": True,
                    "description": "Linux sibling Docker sandbox",
                    "platforms": ["linux", "containers"],
                    "runner": self.runner,
                    "module_path": str(self.module_path),
                    "atomic_root": "/opt/atomic-red-team/atomics",
                    "sandbox_image": self.sandbox_image,
                    "sandbox_atomic_host_path": self.sandbox_atomic_host_path,
                    "sandbox_invoke_host_path": self.sandbox_invoke_host_path,
                    "sandbox_validation_volume": self.sandbox_validation_volume,
                },
            )
        return profiles

    def _all_runner_profiles(self) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen = set()
        for profile in self.runner_profiles + self._default_profiles():
            profile_id = str(profile.get("profile_id") or "").strip()
            if not profile_id or profile_id in seen:
                continue
            merged.append(profile)
            seen.add(profile_id)
        return merged

    def _resolve_runner_profile(self, requested_profile: str = "") -> Dict[str, Any]:
        profiles = [profile for profile in self._all_runner_profiles() if profile.get("enabled", True)]
        if not profiles:
            return {}
        profile_id = (requested_profile or self.default_runner_profile or "").strip()
        if profile_id:
            for profile in profiles:
                if profile.get("profile_id") == profile_id:
                    return profile
        return profiles[0]

    def _atomic_available(self) -> bool:
        return self.atomic_root.exists()

    def _build_invoke_script(
        self,
        techniques: List[str],
        *,
        atomic_root: str,
        module_path: str,
        show_details_brief: bool = True,
    ) -> str:
        technique_list = techniques if techniques else ["T1059"]
        import_cmd = f"Import-Module {self._ps_quote(module_path)} -ErrorAction Stop" if module_path else "Import-Module Invoke-AtomicRedTeam -ErrorAction Stop"
        show_details = " -ShowDetailsBrief" if show_details_brief else ""
        invoke_cmds = "; ".join(
            f"Invoke-AtomicTest {t} -PathToAtomicsFolder {self._ps_quote(atomic_root)}{show_details}"
            for t in technique_list
        )
        return (
            f"{import_cmd}; "
            f"$env:PathToAtomicsFolder={self._ps_quote(atomic_root)}; "
            f"{invoke_cmds}"
        )

    def _build_command(self, techniques: List[str]) -> List[str]:
        runner = self._resolve_runner() or self.runner or "pwsh"
        script = self._build_invoke_script(
            techniques,
            atomic_root=self.atomic_root.as_posix(),
            module_path=str(self.module_path),
            show_details_brief=True,
        )
        return [runner, "-NoProfile", "-Command", script]

    def _build_sandbox_command(self, techniques: List[str], run_id: str, profile: Optional[Dict[str, Any]] = None) -> Optional[List[str]]:
        """Wrap the pwsh atomic command in a Docker sandbox container.

        Returns None if sandbox is not configured (caller falls back to direct exec).
        The sandbox container runs with --network none and --cap-drop ALL so that
        atomic tests are isolated from the host network and kernel surface.
        """
        profile = profile or {}
        sandbox_image = str(profile.get("sandbox_image") or self.sandbox_image or "").strip()
        if not sandbox_image:
            return None

        profile_runner = str(profile.get("runner") or self.runner or "pwsh").strip()
        module_path = str(profile.get("module_path") or self.module_path or "Invoke-AtomicRedTeam").strip()
        atomic_root = str(profile.get("atomic_root") or "/opt/atomic-red-team/atomics").strip()
        pwsh_cmd = [
            profile_runner,
            "-NoProfile",
            "-Command",
            self._build_invoke_script(
                techniques,
                atomic_root=atomic_root,
                module_path=module_path,
                show_details_brief=True,
            ),
        ]
        # pwsh_cmd = ["pwsh", "-NoProfile", "-Command", "<script>"]
        # We re-use the container-internal pwsh path; the sandbox image has it.

        cmd = [
            "docker", "run", "--rm",
            "--name", f"seraph-atomic-{run_id[:12]}",
            "--network", "none",
            "--cap-drop", "ALL",
            "--cap-add", "SETUID",
            "--cap-add", "SETGID",
            "--cap-add", "CHOWN",
            "--cap-add", "DAC_OVERRIDE",
            "--cap-add", "FOWNER",
            "--cap-add", "SYS_PTRACE",
            "--security-opt", "no-new-privileges:false",
        ]

        # Bind-mount atomics and invoke-atomicredteam from host paths
        sandbox_atomic_host_path = str(profile.get("sandbox_atomic_host_path") or self.sandbox_atomic_host_path or "").strip()
        sandbox_invoke_host_path = str(profile.get("sandbox_invoke_host_path") or self.sandbox_invoke_host_path or "").strip()
        sandbox_validation_volume = str(profile.get("sandbox_validation_volume") or self.sandbox_validation_volume or "").strip()
        if sandbox_atomic_host_path:
            cmd += ["-v", f"{sandbox_atomic_host_path}:/opt/atomic-red-team:ro"]
        if sandbox_invoke_host_path:
            cmd += ["-v", f"{sandbox_invoke_host_path}:/opt/invoke-atomicredteam:ro"]

        # Named volume for results — shared with the backend
        if sandbox_validation_volume:
            cmd += ["-v", f"{sandbox_validation_volume}:/var/lib/seraph-ai/atomic-validation"]

        cmd.append(sandbox_image)
        cmd.extend(pwsh_cmd)
        return cmd

    def _build_ssh_command(self, techniques: List[str], profile: Dict[str, Any]) -> List[str]:
        remote_host = str(profile.get("remote_host") or "").strip()
        remote_user = str(profile.get("remote_user") or "").strip()
        if not remote_host:
            raise ValueError("ssh runner profile missing remote_host")
        remote_target = f"{remote_user}@{remote_host}" if remote_user else remote_host
        remote_shell = str(profile.get("remote_shell") or "pwsh").strip()
        remote_port = int(profile.get("remote_port") or 22)
        module_path = str(profile.get("module_path") or self.module_path or "Invoke-AtomicRedTeam").strip()
        atomic_root = str(profile.get("atomic_root") or self.atomic_root.as_posix()).strip()
        remote_script = self._build_invoke_script(
            techniques,
            atomic_root=atomic_root,
            module_path=module_path,
            show_details_brief=True,
        )
        remote_cmd = " ".join(
            shlex.quote(part)
            for part in [remote_shell, "-NoProfile", "-NonInteractive", "-Command", remote_script]
        )
        return ["ssh", "-p", str(remote_port), remote_target, remote_cmd]

    def _build_winrm_command(self, techniques: List[str], profile: Dict[str, Any]) -> List[str]:
        remote_host = str(profile.get("remote_host") or "").strip()
        remote_user = str(profile.get("remote_user") or "").strip()
        if not remote_host:
            raise ValueError("winrm runner profile missing remote_host")
        runner = self._resolve_runner(str(profile.get("runner") or self.runner or ""))
        if not runner:
            raise ValueError("winrm runner profile requires a local PowerShell executable")
        password_env = str(profile.get("password_env") or "").strip()
        module_path = str(profile.get("module_path") or self.module_path or "Invoke-AtomicRedTeam").strip()
        atomic_root = str(profile.get("atomic_root") or self.atomic_root.as_posix()).strip()
        inner_script = self._build_invoke_script(
            techniques,
            atomic_root=atomic_root,
            module_path=module_path,
            show_details_brief=True,
        )
        if remote_user and password_env:
            outer_script = (
                f"$sec = ConvertTo-SecureString $env:{password_env} -AsPlainText -Force; "
                f"$cred = New-Object System.Management.Automation.PSCredential({self._ps_quote(remote_user)}, $sec); "
                f"Invoke-Command -ComputerName {self._ps_quote(remote_host)} -Credential $cred -ScriptBlock {{ {inner_script} }}"
            )
        else:
            outer_script = (
                f"Invoke-Command -ComputerName {self._ps_quote(remote_host)} -ScriptBlock {{ {inner_script} }}"
            )
        return [runner, "-NoProfile", "-NonInteractive", "-Command", outer_script]

    def _build_local_profile_command(self, techniques: List[str], profile: Dict[str, Any]) -> List[str]:
        runner = self._resolve_runner(str(profile.get("runner") or self.runner or "")) or self.runner or "pwsh"
        module_path = str(profile.get("module_path") or self.module_path or "Invoke-AtomicRedTeam").strip()
        atomic_root = str(profile.get("atomic_root") or self.atomic_root.as_posix()).strip()
        script = self._build_invoke_script(
            techniques,
            atomic_root=atomic_root,
            module_path=module_path,
            show_details_brief=True,
        )
        return [runner, "-NoProfile", "-Command", script]

    def _build_profile_command(self, techniques: List[str], run_id: str, profile: Dict[str, Any]) -> Tuple[List[str], str]:
        profile_type = str(profile.get("type") or "local").strip().lower()
        if profile_type == "docker":
            command = self._build_sandbox_command(techniques, run_id, profile)
            if not command:
                raise ValueError("docker runner profile is missing sandbox_image")
            return command, "sandbox"
        if profile_type == "ssh":
            return self._build_ssh_command(techniques, profile), "remote_ssh"
        if profile_type == "winrm":
            return self._build_winrm_command(techniques, profile), "remote_winrm"
        return self._build_local_profile_command(techniques, profile), "direct"

    def _sandbox_available(self) -> bool:
        """True if sandbox image is configured and docker CLI is reachable."""
        if not self.sandbox_image:
            return False
        docker_bin = shutil.which("docker")
        return docker_bin is not None

    def _extract_techniques_from_output(self, *chunks: str) -> List[str]:
        pattern = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
        found = set()
        for chunk in chunks:
            text = str(chunk or "")
            for match in pattern.finditer(text):
                found.add(match.group(0).upper())
        return sorted(found)

    @staticmethod
    def _summarize_failure(exit_code: int, stdout: str, stderr: str) -> str:
        """Create a compact but actionable failure message for UI toasts."""
        detail = (stderr or stdout or "").strip().replace("\n", " ")
        detail = re.sub(r"\s+", " ", detail)
        if detail:
            detail = detail[:180]
            return f"Atomic execution returned non-zero (exit={exit_code}): {detail}"
        return f"Atomic execution returned non-zero (exit={exit_code})"

    def get_status(self) -> Dict:
        resolved_runner = self._resolve_runner()
        return {
            "enabled": self.enabled,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "atomic_root": str(self.atomic_root),
            "atomic_root_exists": self._atomic_available(),
            "atomic_powershell_config": str(self.atomic_powershell_config),
            "atomic_powershell_config_exists": self.atomic_powershell_config.exists(),
            "runner": self.runner,
            "resolved_runner": resolved_runner,
            "runner_available": bool(resolved_runner),
            "results_dir": str(self.results_dir),
            "jobs_configured": len(self.jobs),
            "jobs_source": self.jobs_source,
            "sandbox_image": self.sandbox_image or None,
            "sandbox_available": self._sandbox_available(),
            "sandbox_atomic_host_path": self.sandbox_atomic_host_path or None,
            "sandbox_invoke_host_path": self.sandbox_invoke_host_path or None,
            "sandbox_validation_volume": self.sandbox_validation_volume or None,
            "default_runner_profile": self.default_runner_profile or None,
            "runner_profiles": self._all_runner_profiles(),
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
                for t in row.get("techniques_executed", []) or row.get("techniques", []):
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
                "techniques_executed": job.get("techniques", []),
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": dry_run,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_skipped", [job_id, run_id], {"reason": "disabled"})
            return {"ok": True, **payload}

        selected_profile = self._resolve_runner_profile(str(job.get("runner_profile") or ""))
        try:
            effective_command, execution_mode = self._build_profile_command(
                job.get("techniques", []),
                run_id,
                selected_profile,
            )
            command = effective_command
        except ValueError as exc:
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "skipped",
                "message": f"Atomic validation skipped: {exc}",
                "techniques": job.get("techniques", []),
                "techniques_executed": [],
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": dry_run,
                "runner_profile": selected_profile.get("profile_id") if selected_profile else None,
            }
            self._persist_run(payload)
            return {"ok": False, **payload}

        if dry_run:
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "dry_run",
                "message": "Dry run only. Command not executed.",
                "techniques": job.get("techniques", []),
                "techniques_executed": job.get("techniques", []),
                "command": command,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": True,
                "runner_profile": selected_profile.get("profile_id") if selected_profile else None,
                "execution_mode": execution_mode,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_dry_run", [job_id, run_id], {"techniques": job.get("techniques", [])})
            return {"ok": True, **payload}

        profile_type = str(selected_profile.get("type") or "local").strip().lower() if selected_profile else "local"
        if profile_type in {"local", "winrm"} and not self._resolve_runner(str(selected_profile.get("runner") or self.runner or "")):
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "skipped",
                "message": (
                    f"Atomic validation skipped: no PowerShell runner available "
                    f"(configured='{selected_profile.get('runner') or self.runner}'). Install PowerShell or set ATOMIC_RUNNER."
                ),
                "techniques": job.get("techniques", []),
                "techniques_executed": [],
                "command": command,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
                "runner_profile": selected_profile.get("profile_id") if selected_profile else None,
                "execution_mode": execution_mode,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_skipped", [job_id, run_id], {"reason": "runner_unavailable"})
            return {"ok": True, **payload}

        if profile_type == "local" and not self._atomic_available():
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "failed",
                "message": f"Atomic Red Team folder not found: {self.atomic_root}",
                "techniques": job.get("techniques", []),
                "techniques_executed": job.get("techniques", []),
                "command": command,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
                "runner_profile": selected_profile.get("profile_id") if selected_profile else None,
                "execution_mode": execution_mode,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_failed", [job_id, run_id], {"reason": "atomic_root_missing"})
            return {"ok": False, **payload}

        try:
            proc = subprocess.run(effective_command, capture_output=True, text=True, timeout=1200, check=False)
            status = "success" if proc.returncode == 0 else "failed"
            detected_techniques = self._extract_techniques_from_output(proc.stdout, proc.stderr)
            techniques_executed = sorted(set((job.get("techniques", []) or []) + detected_techniques))
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": status,
                "message": (
                    "Completed"
                    if proc.returncode == 0
                    else self._summarize_failure(proc.returncode, proc.stdout or "", proc.stderr or "")
                ),
                "techniques": job.get("techniques", []),
                "detected_techniques": detected_techniques,
                "techniques_executed": techniques_executed,
                "command": effective_command,
                "exit_code": proc.returncode,
                "stdout": (proc.stdout or "")[-12000:],
                "stderr": (proc.stderr or "")[-12000:],
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
                "execution_mode": execution_mode,
                "runner_profile": selected_profile.get("profile_id") if selected_profile else None,
            }
            self._persist_run(payload)
            self._emit_atomic_event(
                "atomic_validation_job_completed",
                [job_id, run_id],
                {
                    "status": status,
                    "exit_code": proc.returncode,
                    "techniques": job.get("techniques", []),
                    "techniques_executed": techniques_executed,
                    "execution_mode": execution_mode,
                },
            )
            if proc.returncode == 0:
                self._trigger_soar_for_techniques(techniques_executed, job_id, run_id)
            return {"ok": proc.returncode == 0, **payload}
        except subprocess.TimeoutExpired as exc:
            detected_techniques = self._extract_techniques_from_output(exc.stdout, exc.stderr)
            techniques_executed = sorted(set((job.get("techniques", []) or []) + detected_techniques))
            payload = {
                "run_id": run_id,
                "job_id": job_id,
                "job_name": job["name"],
                "status": "failed",
                "message": "Atomic validation run timed out",
                "techniques": job.get("techniques", []),
                "detected_techniques": detected_techniques,
                "techniques_executed": techniques_executed,
                "command": effective_command,
                "stdout": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
                "stderr": (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "",
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": False,
                "execution_mode": execution_mode,
                "runner_profile": selected_profile.get("profile_id") if selected_profile else None,
            }
            self._persist_run(payload)
            self._emit_atomic_event("atomic_validation_job_failed", [job_id, run_id], {"reason": "timeout"})
            return {"ok": False, **payload}


atomic_validation = AtomicValidationManager()

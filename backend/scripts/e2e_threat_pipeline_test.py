#!/usr/bin/env python3
"""
High-level threat simulation E2E test for Seraph/Metatron.

This suite validates end-to-end pipeline movement:
ingest -> detection -> governance queue -> approval -> executor -> feedback surfaces.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


BASE_URL = "http://127.0.0.1:8001/api"
REPORT_DIR = Path("test_reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)
JSON_REPORT = REPORT_DIR / "threat_pipeline_e2e_report.json"
MD_REPORT = REPORT_DIR / "threat_pipeline_e2e_report.md"
AGENT_ENROLLMENT_KEY = "dev-agent-secret-change-in-production"


@dataclass
class StepResult:
    name: str
    passed: bool
    status_code: int
    latency_ms: float
    details: str = ""


class ThreatPipelineE2E:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.token: Optional[str] = None
        self.results: List[StepResult] = []
        self.artifacts: Dict[str, Any] = {}

    def _auth_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        name: str,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        expected_codes: Optional[List[int]] = None,
    ) -> requests.Response:
        expected = expected_codes or [200, 201]
        merged_headers = self._auth_headers()
        if headers:
            merged_headers.update(headers)
        url = f"{BASE_URL}{path}"
        started = time.perf_counter()
        resp = self.session.request(method, url, json=json_body, headers=merged_headers, timeout=45)
        latency_ms = (time.perf_counter() - started) * 1000
        passed = resp.status_code in expected
        details = ""
        if not passed:
            details = resp.text[:300]
        self.results.append(
            StepResult(
                name=name,
                passed=passed,
                status_code=resp.status_code,
                latency_ms=latency_ms,
                details=details,
            )
        )
        return resp

    def _register_and_login(self) -> None:
        suffix = uuid.uuid4().hex[:8]
        email = f"threat-e2e-{suffix}@local"
        password = "ChangeMe123!"
        self._request(
            "register_user",
            "POST",
            "/auth/register",
            json_body={"email": email, "password": password, "name": "Threat E2E"},
            expected_codes=[200, 201, 400],
        )
        login = self._request(
            "login_user",
            "POST",
            "/auth/login",
            json_body={"email": email, "password": password},
            expected_codes=[200],
        )
        data = login.json()
        self.token = data.get("access_token")
        if not self.token:
            raise RuntimeError("Authentication failed: access_token missing")
        self.artifacts["user_email"] = email

    def _simulate_ingest_and_detection(self) -> None:
        # 1) Threat ingestion
        threat_resp = self._request(
            "create_threat",
            "POST",
            "/threats",
            json_body={
                "name": f"Ransomware Campaign {uuid.uuid4().hex[:6]}",
                "type": "ransomware",
                "severity": "critical",
                "source_ip": "203.0.113.55",
                "target_system": "finance-workstation-07",
                "description": "Simulated multi-stage threat for E2E pipeline test",
                "indicators": ["suspicious_ps_exec", "mass_file_rename", "shadowcopy_delete"],
            },
            expected_codes=[200, 201],
        )
        threat = threat_resp.json()
        self.artifacts["threat_id"] = threat.get("id")

        # 2) AI CLI behavior analysis (AATL)
        aatl_resp = self._request(
            "aatl_analyze_cli_session",
            "POST",
            "/ai-threats/aatl/analyze",
            json_body={
                "host_id": "finance-workstation-07",
                "session_id": f"sess-{uuid.uuid4().hex[:8]}",
                "commands": [
                    {"command": "whoami", "ts": datetime.now(timezone.utc).isoformat()},
                    {"command": "nltest /dclist:corp.local", "ts": datetime.now(timezone.utc).isoformat()},
                    {"command": "vssadmin delete shadows /all /quiet", "ts": datetime.now(timezone.utc).isoformat()},
                    {"command": "powershell -enc SQBFAFgA", "ts": datetime.now(timezone.utc).isoformat()},
                ],
            },
            expected_codes=[200, 201],
        )
        self.artifacts["aatl_response"] = aatl_resp.json()

        # 3) Email threat detection
        email_resp = self._request(
            "email_protection_analyze",
            "POST",
            "/email-protection/analyze",
            json_body={
                "sender": "accounts-payable@lookalike-vendor-secure.com",
                "recipient": "finance-team@corp.local",
                "subject": "Urgent wire transfer approval needed",
                "body": "Please open attachment and complete payment today.",
                "attachments": [{"filename": "wire-transfer.xlsm", "size": 124000}],
                "sender_ip": "198.51.100.23",
            },
            expected_codes=[200, 201],
        )
        email_data = email_resp.json()
        self.artifacts["email_assessment_id"] = email_data.get("assessment_id")
        self.artifacts["email_threat_score"] = email_data.get("threat_score")

        # 4) Browser isolation session
        browser_resp = self._request(
            "browser_isolation_session_create",
            "POST",
            "/browser-isolation/sessions",
            json_body={"url": "https://suspicious-auth-gateway.invalid/login", "isolation_mode": "full"},
            expected_codes=[200, 201],
        )
        browser_data = browser_resp.json()
        self.artifacts["browser_session_id"] = browser_data.get("session_id")

        # 5) Mobile threat signal
        device_name = f"e2e-mobile-{uuid.uuid4().hex[:6]}"
        mobile_resp = self._request(
            "mobile_register_device",
            "POST",
            "/mobile-security/devices",
            json_body={
                "device_name": device_name,
                "platform": "android",
                "os_version": "14",
                "model": "Pixel 8",
                "serial_number": f"SN-{uuid.uuid4().hex[:10]}",
                "user_email": "analyst@corp.local",
            },
            expected_codes=[200, 201],
        )
        mobile_data = mobile_resp.json()
        device_id = mobile_data.get("device_id")
        self.artifacts["mobile_device_id"] = device_id
        if device_id:
            self._request(
                "mobile_update_device_status",
                "PUT",
                f"/mobile-security/devices/{device_id}/status",
                json_body={
                    "is_jailbroken": True,
                    "is_encrypted": False,
                    "has_passcode": False,
                    "mdm_enrolled": False,
                    "network_info": {"wifi": "rogue-ap", "mitm_detected": True},
                },
                expected_codes=[200],
            )

    def _simulate_governed_response_pipeline(self) -> None:
        # Baseline governance pending count
        pending_before_resp = self._request(
            "governance_pending_before",
            "GET",
            "/governance/decisions/pending?limit=100",
            expected_codes=[200],
        )
        pending_before = int((pending_before_resp.json() or {}).get("count", 0))
        self.artifacts["pending_before"] = pending_before

        # 6) Register an agent via enrollment-key path
        agent_id = f"e2e-agent-{uuid.uuid4().hex[:8]}"
        self.artifacts["agent_id"] = agent_id
        reg_resp = self._request(
            "unified_agent_register",
            "POST",
            "/unified/agents/register",
            json_body={
                "agent_id": agent_id,
                "platform": "linux",
                "hostname": "finance-workstation-07",
                "ip_address": "10.10.20.15",
                "version": "7.0.0",
                "capabilities": ["process", "network", "registry", "edr"],
            },
            headers={"x-enrollment-key": AGENT_ENROLLMENT_KEY},
            expected_codes=[200, 201],
        )
        reg_data = reg_resp.json()
        self.artifacts["agent_auth_token_present"] = bool(reg_data.get("auth_token"))

        # 7) Heartbeat telemetry submission
        self._request(
            "unified_agent_heartbeat",
            "POST",
            f"/unified/agents/{agent_id}/heartbeat",
            json_body={
                "agent_id": agent_id,
                "status": "online",
                "cpu_usage": 81,
                "memory_usage": 77,
                "threat_count": 3,
                "network_connections": 124,
                "alerts": [
                    {"type": "privilege_escalation", "severity": "high"},
                    {"type": "ransomware_behavior", "severity": "critical"},
                ],
                "monitors": {
                    "registry": {"events": 12, "detections": 2, "enabled": True},
                    "process_tree": {"events": 34, "detections": 3, "enabled": True},
                    "firewall": {"events": 15, "detections": 2, "enabled": True},
                },
            },
            headers={"x-enrollment-key": AGENT_ENROLLMENT_KEY},
            expected_codes=[200],
        )

        # 8) Propose high-impact remediation -> outbound gate / governance queue
        proposal_resp = self._request(
            "remediation_propose_block_ip",
            "POST",
            f"/unified/agents/{agent_id}/remediation/propose",
            json_body={
                "action": "block_ip",
                "parameters": {"ip": "203.0.113.55"},
                "priority": "critical",
                "reason": "Threat simulation escalation",
            },
            headers={"x-enrollment-key": AGENT_ENROLLMENT_KEY},
            expected_codes=[200],
        )
        proposal = proposal_resp.json()
        decision_id = proposal.get("decision_id")
        self.artifacts["decision_id"] = decision_id
        self.artifacts["proposal_status"] = proposal.get("status")

        # 9) Verify pending increased or decision is visible
        pending_after_resp = self._request(
            "governance_pending_after",
            "GET",
            "/governance/decisions/pending?limit=200",
            expected_codes=[200],
        )
        pending_after_payload = pending_after_resp.json() or {}
        pending_after = int(pending_after_payload.get("count", 0))
        self.artifacts["pending_after"] = pending_after
        items = pending_after_payload.get("items") or []
        self.artifacts["decision_present_in_pending"] = bool(
            decision_id and any(item.get("decision_id") == decision_id for item in items)
        )

        # 10) Approve decision and run executor to complete movement
        if decision_id:
            approve_resp = self._request(
                "governance_approve_decision",
                "POST",
                f"/governance/decisions/{decision_id}/approve",
                json_body={"reason": "E2E threat pipeline approval"},
                expected_codes=[200],
            )
            approve_payload = approve_resp.json() or {}
            summary = approve_payload.get("execution_summary") or {}
            self.artifacts["approve_execution_summary"] = summary

        exec_resp = self._request(
            "governance_executor_run_once",
            "POST",
            "/governance/executor/run-once",
            json_body={"limit": 100},
            expected_codes=[200],
        )
        self.artifacts["executor_summary"] = (exec_resp.json() or {}).get("summary")

    def _validate_feedback_surfaces(self) -> None:
        # Correlation and threat intelligence surfaces
        corr_resp = self._request(
            "correlation_all_active",
            "POST",
            "/correlation/all-active",
            expected_codes=[200],
        )
        corr_payload = corr_resp.json() or {}
        self.artifacts["correlation_summary"] = corr_payload.get("summary")

        # Timeline and audit availability
        timeline_resp = self._request(
            "timeline_recent",
            "GET",
            "/timelines/recent?limit=25",
            expected_codes=[200],
        )
        timeline_payload = timeline_resp.json() or {}
        self.artifacts["timeline_count"] = int(timeline_payload.get("count", 0))

        audit_resp = self._request(
            "audit_recent",
            "GET",
            "/audit/recent?limit=25",
            expected_codes=[200],
        )
        try:
            audit_data = audit_resp.json()
            self.artifacts["audit_recent_count"] = len(audit_data) if isinstance(audit_data, list) else 0
        except Exception:
            self.artifacts["audit_recent_count"] = 0

        mitre_resp = self._request(
            "mitre_coverage_snapshot",
            "GET",
            "/mitre/coverage",
            expected_codes=[200],
        )
        mitre_payload = mitre_resp.json() or {}
        self.artifacts["mitre_snapshot"] = {
            "coverage_percent_gte3": mitre_payload.get("coverage_percent_gte3"),
            "covered_score_gte3": mitre_payload.get("covered_score_gte3"),
            "covered_score_gte4": mitre_payload.get("covered_score_gte4"),
            "observed_techniques": mitre_payload.get("observed_techniques"),
        }

    def _pipeline_assertions(self) -> List[StepResult]:
        assertions: List[StepResult] = []

        def add(name: str, ok: bool, details: str = "") -> None:
            assertions.append(StepResult(name=name, passed=ok, status_code=200 if ok else 500, latency_ms=0.0, details=details))

        add(
            "assert_ingest_artifacts_created",
            bool(self.artifacts.get("threat_id") and self.artifacts.get("email_assessment_id") and self.artifacts.get("mobile_device_id")),
            f"artifacts={self.artifacts.get('threat_id')},{self.artifacts.get('email_assessment_id')},{self.artifacts.get('mobile_device_id')}",
        )
        add(
            "assert_governance_queue_created",
            self.artifacts.get("proposal_status") == "queued_for_triune_approval",
            f"proposal_status={self.artifacts.get('proposal_status')}",
        )
        add(
            "assert_decision_visible_or_pending_increased",
            bool(self.artifacts.get("decision_present_in_pending"))
            or int(self.artifacts.get("pending_after", 0)) > int(self.artifacts.get("pending_before", 0)),
            f"pending_before={self.artifacts.get('pending_before')} pending_after={self.artifacts.get('pending_after')} decision_visible={self.artifacts.get('decision_present_in_pending')}",
        )
        summary = self.artifacts.get("approve_execution_summary") or {}
        add(
            "assert_approved_decision_executed",
            int(summary.get("executed", 0)) >= 1 or int(summary.get("processed", 0)) >= 1,
            f"approve_summary={summary}",
        )
        mitre = self.artifacts.get("mitre_snapshot") or {}
        add(
            "assert_mitre_feedback_available",
            bool(mitre.get("covered_score_gte3")) and bool(mitre.get("coverage_percent_gte3")),
            f"mitre_snapshot={mitre}",
        )

        return assertions

    def run(self) -> Dict[str, Any]:
        self._register_and_login()
        self._simulate_ingest_and_detection()
        self._simulate_governed_response_pipeline()
        self._validate_feedback_surfaces()

        assertion_steps = self._pipeline_assertions()
        self.results.extend(assertion_steps)

        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        pass_rate = (passed / total * 100.0) if total else 0.0
        avg_latency = sum(r.latency_ms for r in self.results if r.latency_ms > 0) / max(
            1, sum(1 for r in self.results if r.latency_ms > 0)
        )
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "base_url": BASE_URL,
            "total_steps": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(pass_rate, 2),
            "avg_latency_ms": round(avg_latency, 2),
            "artifacts": self.artifacts,
            "steps": [asdict(step) for step in self.results],
        }
        return report


def write_reports(report: Dict[str, Any]) -> None:
    JSON_REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Threat Pipeline E2E Report",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Base URL: `{report['base_url']}`",
        f"- Total Steps: **{report['total_steps']}**",
        f"- Passed: **{report['passed']}**",
        f"- Failed: **{report['failed']}**",
        f"- Pass Rate: **{report['pass_rate']}%**",
        f"- Avg Latency: **{report['avg_latency_ms']} ms**",
        "",
        "## Pipeline Artifacts",
        "",
        "```json",
        json.dumps(report.get("artifacts", {}), indent=2),
        "```",
        "",
        "## Step Results",
        "",
        "| Step | Result | HTTP | Latency (ms) | Details |",
        "|---|---|---:|---:|---|",
    ]
    for step in report.get("steps", []):
        icon = "PASS" if step["passed"] else "FAIL"
        details = (step.get("details") or "").replace("|", "/")
        lines.append(
            f"| `{step['name']}` | {icon} | {step['status_code']} | {step['latency_ms']:.2f} | {details} |"
        )
    MD_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    runner = ThreatPipelineE2E()
    report = runner.run()
    write_reports(report)
    print(json.dumps({k: report[k] for k in ["total_steps", "passed", "failed", "pass_rate", "avg_latency_ms"]}, indent=2))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

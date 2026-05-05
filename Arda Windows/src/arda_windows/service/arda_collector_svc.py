"""
ARDA Collector Windows Service
===============================
Runs as a Windows Service (SYSTEM account) and exposes a local HTTP API on
127.0.0.1:7331.  WorldManifold is built once on start and polled every 60 s
in a background thread; the HTTP server always returns the most recent snapshot.

Install / manage:
  python arda_collector_svc.py install
  python arda_collector_svc.py start
  python arda_collector_svc.py stop
  python arda_collector_svc.py remove

Endpoints:
  GET /health
  GET /summary
  GET /sovereignty
  GET /pcrs
  GET /secure-boot
  GET /evidence/<ainur>   ainur ∈ {varda, ulmo, manwe, mandos}
"""

import json
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

# pywin32 — gracefully absent during development on Linux
try:
    import win32event
    import win32service
    import win32serviceutil
    _WIN32 = True
except ImportError:
    _WIN32 = False

# ---------------------------------------------------------------------------
# Telemetry cache (refreshed by background thread)
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()
_CACHE: dict = {}
_MANIFOLD = None


def _refresh(manifold) -> None:
    """Collect a full snapshot and store it in the cache."""
    snap: dict = {"timestamp": time.time(), "errors": {}}

    try:
        snap["summary"] = manifold.platform_summary()
    except Exception as exc:
        snap["errors"]["summary"] = str(exc)

    try:
        sv = manifold.sovereignty.evaluate_sovereignty_state()
        snap["sovereignty"] = {
            "state": sv.state,
            "reasons": sv.reasons,
            "attributes": sv.attributes,
        }
    except Exception as exc:
        snap["errors"]["sovereignty"] = str(exc)

    try:
        pcrs = manifold.attestation.get_pcr_snapshot([0, 1, 4, 7, 11, 14])
        snap["pcrs"] = [{"index": p.index, "value": p.value, "bank": p.bank} for p in pcrs]
    except Exception as exc:
        snap["errors"]["pcrs"] = str(exc)

    try:
        sb = manifold.attestation.get_secure_boot_state()
        snap["secure_boot"] = {
            "enabled": sb.enabled,
            "setup_mode": sb.setup_mode,
            "mode": sb.secure_boot_mode,
            "pk_enrolled": sb.pk_enrolled,
        }
    except Exception as exc:
        snap["errors"]["secure_boot"] = str(exc)

    evidence: dict = {}
    for ainur in ("varda", "ulmo", "manwe", "mandos"):
        try:
            collector = getattr(manifold.evidence, f"collect_{ainur}_evidence")
            pkt = collector({})
            evidence[ainur] = {
                "source": pkt.source,
                "confidence": pkt.confidence,
                "stub": pkt.evidence.get("stub", False),
                "evidence": pkt.evidence,
            }
        except Exception as exc:
            evidence[ainur] = {"error": str(exc)}
    snap["evidence"] = evidence

    with _LOCK:
        _CACHE.clear()
        _CACHE.update(snap)


def _poll_loop(interval: int = 60) -> None:
    global _MANIFOLD
    while True:
        try:
            if _MANIFOLD is not None:
                _refresh(_MANIFOLD)
        except Exception:
            pass
        time.sleep(interval)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence access logs
        pass

    def _json(self, code: int, body) -> None:
        payload = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.rstrip("/")

        with _LOCK:
            snap = dict(_CACHE)

        if path == "/health":
            self._json(200, {"status": "ok", "timestamp": snap.get("timestamp")})

        elif path == "/summary":
            self._json(200, snap.get("summary", {"error": "not ready"}))

        elif path == "/sovereignty":
            self._json(200, snap.get("sovereignty", {"error": "not ready"}))

        elif path == "/pcrs":
            self._json(200, snap.get("pcrs", {"error": "not ready"}))

        elif path == "/secure-boot":
            self._json(200, snap.get("secure_boot", {"error": "not ready"}))

        elif path.startswith("/evidence/"):
            ainur = path.split("/evidence/", 1)[1]
            ev = snap.get("evidence", {})
            if ainur in ev:
                self._json(200, ev[ainur])
            else:
                self._json(404, {"error": f"unknown ainur: {ainur}"})

        else:
            self._json(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Service class
# ---------------------------------------------------------------------------

if _WIN32:
    class ARDACollectorService(win32serviceutil.ServiceFramework):
        _svc_name_ = "ARDACollector"
        _svc_display_name_ = "ARDA Ring-0 Telemetry Collector"
        _svc_description_ = (
            "Collects TPM attestation, Secure Boot state, process lineage, "
            "network flow, and kernel enforcement telemetry via the ARDA adapter "
            "and serves it on http://127.0.0.1:7331."
        )

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._server: HTTPServer | None = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            if self._server:
                self._server.shutdown()

        def SvcDoRun(self):
            global _MANIFOLD
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            try:
                # Bootstrap WorldManifold
                sys.path.insert(0, r"C:\ARDA\src")
                from arda_windows.world_manifold import WorldManifold  # noqa: PLC0415
                _MANIFOLD = WorldManifold.build()

                # Initial snapshot (blocking)
                _refresh(_MANIFOLD)

                # Background poller
                t = threading.Thread(target=_poll_loop, args=(60,), daemon=True)
                t.start()

                # HTTP server
                self._server = HTTPServer(("0.0.0.0", 7331), _Handler)
                self._server.serve_forever()

            except Exception:
                # Write to event log so we can diagnose failures
                import win32evtlogutil  # noqa: PLC0415
                win32evtlogutil.ReportEvent(
                    self._svc_name_,
                    1,
                    eventType=win32evtlogutil.EVENTLOG_ERROR_TYPE,
                    strings=[traceback.format_exc()],
                )
                raise


# ---------------------------------------------------------------------------
# Standalone mode (for testing without the service framework)
# ---------------------------------------------------------------------------

def _run_standalone():
    """Run the collector + HTTP server in the foreground (no pywin32 needed)."""
    global _MANIFOLD
    print("[ARDA] Standalone mode — loading WorldManifold...")
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent.parent))
    from arda_windows.world_manifold import WorldManifold  # noqa: PLC0415
    _MANIFOLD = WorldManifold.build()
    print(f"[ARDA] Platform: {_MANIFOLD.platform_summary()['platform']}")

    print("[ARDA] Initial snapshot...")
    _refresh(_MANIFOLD)
    print(f"[ARDA] Sovereignty: {_CACHE.get('sovereignty', {}).get('state', '?')}")

    t = threading.Thread(target=_poll_loop, args=(60,), daemon=True)
    t.start()

    print("[ARDA] HTTP API on http://0.0.0.0:7331")
    server = HTTPServer(("0.0.0.0", 7331), _Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[ARDA] Stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) == 1 or not _WIN32:
        _run_standalone()
    else:
        win32serviceutil.HandleCommandLine(ARDACollectorService)

"""Pytest bootstrap for backend tests."""

import socket
import sys
from functools import lru_cache
from importlib import import_module
from pathlib import Path
from urllib.parse import urlparse

import pytest


TESTS_DIR = Path(__file__).resolve().parent

if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))


@lru_cache(maxsize=None)
def _base_url_available(base_url: str) -> bool:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return True

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    try:
        with socket.create_connection((parsed.hostname, port), timeout=0.2):
            return True
    except OSError:
        return False


def pytest_collection_modifyitems(config, items):
    for item in items:
        module = getattr(item, "module", None)
        base_url = getattr(module, "BASE_URL", None)
        if not isinstance(base_url, str) or not base_url:
            continue
        if _base_url_available(base_url):
            continue

        item.add_marker(
            pytest.mark.skip(reason=f"test server {base_url!r} is unavailable in this environment")
        )


def _normalize_backend_package_attrs() -> None:
    backend_pkg = sys.modules.get("backend")
    if backend_pkg is None:
        return

    for child in ("services", "routers"):
        child_module = sys.modules.get(f"backend.{child}")
        if child_module is None:
            try:
                child_module = import_module(f"backend.{child}")
            except Exception:
                continue
        setattr(backend_pkg, child, child_module)


def pytest_runtest_setup(item):
    _normalize_backend_package_attrs()

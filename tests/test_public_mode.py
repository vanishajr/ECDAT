"""Tests for public-deploy mode (Render + Netlify).

Local default is loopback-only with no auth. With ``ECDAT_PUBLIC=1`` the
server may bind publicly. There is no API token: the API is open and
guarded only by CORS, a loose Origin/Referer check on mutating routes,
and per-IP rate limits.
"""

import threading
import urllib.request

import pytest

from ecdat.commands import gui_cmd
from ecdat.web import server as web


class _Headers(dict):
    def get(self, key, default=None):  # BaseHTTPRequestHandler-like access
        return super().get(key, default)


def _handler_with_headers(headers: dict, frontend_url: str = "https://app.netlify.app"):
    import os

    os.environ["ECDAT_FRONTEND_URL"] = frontend_url
    handler = web.Handler.__new__(web.Handler)
    handler.headers = _Headers(headers)
    return handler


@pytest.fixture
def _local_env(monkeypatch):
    monkeypatch.delenv("ECDAT_PUBLIC", raising=False)
    return monkeypatch


@pytest.fixture
def _public_env(monkeypatch):
    monkeypatch.setenv("ECDAT_PUBLIC", "1")
    monkeypatch.setenv("ECDAT_FRONTEND_URL", "https://app.netlify.app")
    return monkeypatch


def test_local_default_is_open_loopback_only(_local_env):
    assert web._is_public() is False
    with pytest.raises(ValueError):
        web.make_server("0.0.0.0", 0)


def test_no_token_helpers_remain():
    assert not hasattr(web, "_api_token")
    assert not hasattr(web, "_request_authorized")
    assert not hasattr(web, "_PUBLIC_AUTH_EXEMPT")


def test_origin_check_allows_missing_header(_public_env):
    handler = _handler_with_headers({})
    assert handler._origin_allowed("/api/scan-jobs") is True
    assert handler._origin_allowed("/api/uploads") is True


def test_origin_check_allows_frontend_rejects_evil(_public_env):
    assert _handler_with_headers({"Origin": "https://app.netlify.app"})._origin_allowed("/api/scan-jobs") is True
    assert _handler_with_headers({"Origin": "https://app.netlify.app/"})._origin_allowed("/api/uploads") is True
    assert _handler_with_headers({"Referer": "https://app.netlify.app/some/page"})._origin_allowed("/api/scan-jobs") is True
    assert _handler_with_headers({"Origin": "https://evil.example"})._origin_allowed("/api/scan-jobs") is False
    assert _handler_with_headers({"Referer": "https://evil.netlify.app/"})._origin_allowed("/api/uploads") is False


def test_origin_check_exempts_health_and_oauth(_public_env):
    for path in ("/api/health", "/api/github/oauth/start",
                 "/api/github/oauth/callback"):
        handler = _handler_with_headers({"Origin": "https://evil.example"})
        assert handler._origin_allowed(path) is True


def test_max_upload_bytes_default_and_override(_local_env, monkeypatch):
    assert web._max_upload_bytes() == 250 * 1024 * 1024
    monkeypatch.setenv("ECDAT_MAX_UPLOAD_MB", "50")
    assert web._max_upload_bytes() == 50 * 1024 * 1024
    monkeypatch.setenv("ECDAT_MAX_UPLOAD_MB", "bogus")
    assert web._max_upload_bytes() == 250 * 1024 * 1024


def test_cookie_attrs_local_vs_public(_local_env, monkeypatch):
    assert "SameSite=Lax" in web._session_cookie_attrs(max_age=5)
    assert "Secure" not in web._session_cookie_attrs(max_age=5)
    monkeypatch.setenv("ECDAT_PUBLIC", "1")
    attrs = web._session_cookie_attrs(max_age=5)
    assert "SameSite=None" in attrs and "Secure" in attrs


def test_frontend_allowlist(_local_env, monkeypatch):
    handler = web.Handler.__new__(web.Handler)
    assert handler._frontend_allowed("http://127.0.0.1:5173/") is True
    assert handler._frontend_allowed("https://evil.example/") is False
    monkeypatch.setenv("ECDAT_PUBLIC", "1")
    monkeypatch.setenv("ECDAT_FRONTEND_URL", "https://app.netlify.app")
    assert handler._frontend_url() == "https://app.netlify.app"
    assert handler._frontend_allowed("https://app.netlify.app") is True
    assert handler._frontend_allowed("https://app.netlify.app/") is True
    assert handler._frontend_allowed("https://evil.netlify.app") is False


def test_gui_cmd_still_refuses_non_loopback_locally(_local_env, tmp_path, capsys):
    args = type("Args", (), {"host": "0.0.0.0", "port": 0,
                             "db": str(tmp_path / "t.db")})()
    assert gui_cmd.run(args) != 0
    assert "127.0.0.1" in capsys.readouterr()[1]


def _serve(monkeypatch, tmp_path):
    monkeypatch.setenv("ECDAT_PUBLIC", "1")
    monkeypatch.setenv("ECDAT_FRONTEND_URL", "https://app.netlify.app")
    srv = web.make_server("127.0.0.1", 0, db_path=str(tmp_path / "pub.db"))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread


def _get(port, path, origin=None):
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if origin:
        request.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def _post(port, path, payload=b"{}", origin=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=payload, method="POST",
        headers={"Content-Type": "application/json"})
    if origin:
        request.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_rate_limit_allows_then_blocks():
    from types import SimpleNamespace

    state = SimpleNamespace(lock=threading.RLock(), rate_hits={})
    path = "/api/scan-jobs"
    limit, _window = web._RATE_LIMITS[path]
    for _ in range(limit):
        assert web._check_rate_limit(state, path, "1.2.3.4") is True
    assert web._check_rate_limit(state, path, "1.2.3.4") is False
    # Other IPs and unlisted paths are unaffected.
    assert web._check_rate_limit(state, path, "5.6.7.8") is True
    assert web._check_rate_limit(state, "/api/health", "1.2.3.4") is True


def test_rate_limit_allows_openssl_size_upload_burst():
    """A single OpenSSL-size analysis uploads one POST per file (~3k)."""
    from types import SimpleNamespace

    state = SimpleNamespace(lock=threading.RLock(), rate_hits={})
    for _ in range(3000):
        assert web._check_rate_limit(state, "/api/uploads", "203.0.113.9") is True


def test_rate_limit_window_expiry():
    import threading
    import time
    from collections import deque
    from types import SimpleNamespace

    state = SimpleNamespace(lock=threading.RLock(), rate_hits={})
    path = "/api/uploads"
    limit, window = web._RATE_LIMITS[path]
    old = time.monotonic() - window - 1
    state.rate_hits[("9.9.9.9", path)] = deque([old] * limit)
    assert web._check_rate_limit(state, path, "9.9.9.9") is True


def test_client_ip_prefers_forwarded_for():
    class Fake:
        headers = {"X-Forwarded-For": "203.0.113.7, 10.0.0.1"}
        client_address = ("10.0.0.9", 1234)

    assert web._client_ip(Fake()) == "203.0.113.7"

    class Direct:
        headers = {}
        client_address = ("10.0.0.9", 1234)

    assert web._client_ip(Direct()) == "10.0.0.9"


def test_live_public_no_token_required(tmp_path, monkeypatch):
    import urllib.error  # noqa: F401  (kept local to the live test)

    srv, thread = _serve(monkeypatch, tmp_path)
    try:
        port = srv.server_address[1]
        assert _get(port, "/api/health") == 200
        # Open API: no token needed, with or without Origin.
        assert _get(port, "/api/scans") == 200
        # Mutating route without Origin is allowed (same-origin proxy).
        assert _post(port, "/api/scan-jobs") in (400, 500)
        # Mutating route with evil Origin is rejected.
        assert _post(port, "/api/scan-jobs", origin="https://evil.example") == 403
        # Mutating route with frontend Origin passes the origin gate
        # (then fails on bad payload, proving it reached the handler).
        assert _post(port, "/api/scan-jobs", origin="https://app.netlify.app") in (400, 500)
    finally:
        srv.shutdown()
        thread.join(timeout=10)
        srv.server_close()

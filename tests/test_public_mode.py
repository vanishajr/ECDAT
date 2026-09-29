"""Tests for public-deploy mode (Render + Netlify).

Local default is unchanged: loopback-only, no token. With
``ECDAT_PUBLIC=1`` the server may bind publicly and (when
``ECDAT_API_TOKEN`` is set) requires a Bearer token on /api/* except
the health check and the GitHub OAuth browser navigations.
"""

import threading
import urllib.request

import pytest

from ecdat.commands import gui_cmd
from ecdat.web import server as web


class _Headers(dict):
    def get(self, key, default=None):  # BaseHTTPRequestHandler-like access
        return super().get(key, default)


@pytest.fixture
def _local_env(monkeypatch):
    monkeypatch.delenv("ECDAT_PUBLIC", raising=False)
    monkeypatch.delenv("ECDAT_API_TOKEN", raising=False)
    return monkeypatch


@pytest.fixture
def _public_env(monkeypatch):
    monkeypatch.setenv("ECDAT_PUBLIC", "1")
    monkeypatch.setenv("ECDAT_API_TOKEN", "secret-token")
    return monkeypatch


def test_local_default_is_open_loopback_only(_local_env):
    assert web._is_public() is False
    assert web._request_authorized("/api/scans", _Headers()) is True
    with pytest.raises(ValueError):
        web.make_server("0.0.0.0", 0)


def test_public_without_token_stays_open(_public_env, monkeypatch):
    monkeypatch.delenv("ECDAT_API_TOKEN")
    assert web._request_authorized("/api/scans", _Headers()) is True


def test_public_bearer_accept_reject(_public_env):
    assert web._request_authorized("/api/scans", _Headers()) is False
    assert web._request_authorized(
        "/api/scans", _Headers({"Authorization": "Bearer wrong"})) is False
    assert web._request_authorized(
        "/api/scans", _Headers({"Authorization": "Bearer secret-token"})) is True


def test_public_exempt_paths_need_no_token(_public_env):
    for path in ("/api/health", "/api/github/oauth/start",
                 "/api/github/oauth/callback"):
        assert web._request_authorized(path, _Headers()) is True


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
    monkeypatch.setenv("ECDAT_API_TOKEN", "secret-token")
    srv = web.make_server("127.0.0.1", 0, db_path=str(tmp_path / "pub.db"))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread


def _get(port, path, token=None):
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_live_public_auth_flow(tmp_path, monkeypatch):
    import urllib.error  # noqa: F401  (kept local to the live test)

    srv, thread = _serve(monkeypatch, tmp_path)
    try:
        port = srv.server_address[1]
        assert _get(port, "/api/health") == 200
        assert _get(port, "/api/scans") == 401
        assert _get(port, "/api/scans", token="nope") == 401
        assert _get(port, "/api/scans", token="secret-token") == 200
    finally:
        srv.shutdown()
        thread.join(timeout=10)
        srv.server_close()

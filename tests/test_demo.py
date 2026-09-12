"""Tests for Task 27: `ecdat demo` (stdlib + loopback only).

Covers parser registration, workspace seeding through the real
pipeline, startup/shutdown without serving, host refusal, and that
existing CLI/GUI entry points still work. No network beyond
127.0.0.1; serve_forever is stubbed so tests never block.
"""

from pathlib import Path

from ecdat.cli import build_parser, main
from ecdat.commands import demo_cmd
from ecdat.store import db
from ecdat.store import scans as sstore


def test_demo_registered():
    args = build_parser().parse_args(["demo"])
    assert args.func is demo_cmd.run
    assert args.port == 8734


def test_prepare_demo_db_seeds_two_scans(tmp_path):
    info = demo_cmd.prepare_demo_db(tmp_path / "demo.db", tmp_path / "work")
    assert len(info["targets"]) == 2
    assert len(info["scan_ids"]) == 2
    conn = db.open_db(tmp_path / "demo.db")
    try:
        assert sstore.count_scans(conn) == 2
        for scan_id in info["scan_ids"]:
            assert sstore.get_scan(conn, scan_id) is not None
    finally:
        conn.close()


def test_prepare_demo_db_idempotent(tmp_path):
    first = demo_cmd.prepare_demo_db(tmp_path / "demo.db", tmp_path / "work")
    second = demo_cmd.prepare_demo_db(tmp_path / "demo.db", tmp_path / "work")
    assert first["scan_ids"] == second["scan_ids"]
    conn = db.open_db(tmp_path / "demo.db")
    try:
        assert sstore.count_scans(conn) == 2
    finally:
        conn.close()


class _StubServer:
    server_address = ("127.0.0.1", 9999)

    def __init__(self):
        self.closed = False

    def serve_forever(self):
        raise KeyboardInterrupt

    def server_close(self):
        self.closed = True


def test_demo_run_starts_and_stops_cleanly(tmp_path, capsys, monkeypatch):
    stub = _StubServer()
    monkeypatch.setattr(demo_cmd, "make_server", lambda *a, **k: stub)
    rc = main(["demo", "--db", str(tmp_path / "d.db"), "--port", "0"])
    assert rc == 0
    assert stub.closed
    out, _ = capsys.readouterr()
    assert "http://127.0.0.1:9999" in out
    assert "mock" in out.lower()
    assert "Ctrl-C" in out


def test_demo_refuses_non_loopback_host(tmp_path, capsys):
    rc = main(["demo", "--db", str(tmp_path / "d.db"), "--host", "0.0.0.0"])
    assert rc == 1
    _, err = capsys.readouterr()
    assert "loopback" in err


def test_existing_commands_unchanged():
    args = build_parser().parse_args(["gui"])
    assert args.func.__module__ == "ecdat.commands.gui_cmd"
    args = build_parser().parse_args(["ci", "x.py"])
    assert args.func.__module__ == "ecdat.commands.ci_cmd"
    args = build_parser().parse_args(["scan", "x.py"])
    assert args.func.__module__ == "ecdat.commands.scan_cmd"

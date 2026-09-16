"""ecdat demo [--db PATH] [--host 127.0.0.1] [--port PORT].

One-command local SIH demo: seed a demo database through the real
mock pipeline (GuiService submit/poll, no shortcuts) and launch the
loopback-only GUI dashboard on it. Thin orchestration only: parser
lives in ecdat.cli, use cases in ecdat.gui.service, HTTP in
ecdat.gui.server.

Default database is a fresh temporary directory (no hard-coded user
paths; the path is printed). Loopback only, like `ecdat gui`.
Exit 0 on clean shutdown (Ctrl-C), 1 on errors. Mock data only.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from ecdat.commands import ERROR
from ecdat.commands.gui_cmd import DEFAULT_HOST, DEFAULT_PORT
from ecdat.web.server import LOOPBACK_HOSTS

_SEED_FILES = {
    "app": {"m.py": "x = 1  # demo multi-finding target\n"},
    "clean.py": "x = 1  # demo clean target\n",
}

WORKFLOW = (
    "1. Card 1: pick a demo target (or keep the seeded scans).",
    "2. Cards 2-3: preview + mock scan monitor.",
    "3. Card 4: inventory/findings (click rows for Card 6 detail).",
    "4. Card 5: risk dashboard (mock scoring).",
    "5. Card 7: asset inventory + groupings.",
    "6. Card 8: knowledge graph (MOCK DATASET).",
    "7. Card 9: migration planner (MOCK / PLACEHOLDER).",
    "8. Card 10: reports (view/download HTML/PDF/CSV/JSON/SARIF).",
)


def prepare_demo_db(db_path: str | Path, base_dir: str | Path) -> dict:
    """Create demo targets and seed scans via the real pipeline.

    Returns {"db": str, "targets": [...], "scan_ids": [...]}.
    Idempotent: re-running reuses already-stored fixture scans.
    """
    from ecdat.Backup_GUI.service import GuiService

    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    targets = []
    for name, files in _SEED_FILES.items():
        target = base / name
        if isinstance(files, dict):
            target.mkdir(exist_ok=True)
            for fname, content in files.items():
                (target / fname).write_text(content, encoding="utf-8")
        else:
            target.write_text(files, encoding="utf-8")
        targets.append(str(target))
    svc = GuiService(db_path)
    scan_ids = []
    for target in targets:
        job = svc.submit(target)
        snap: dict | None = None
        for _ in range(5):
            snap = svc.status(job["job_id"])
            if snap is not None and snap["status"] == "completed":
                break
        if snap is not None and snap.get("scan_id"):
            scan_ids.append(snap["scan_id"])
    return {"db": str(db_path), "targets": targets, "scan_ids": scan_ids}


def run(args: argparse.Namespace) -> int:
    from ecdat.Backup_GUI.server import make_server

    host = str(args.host)
    if host not in LOOPBACK_HOSTS:
        print(f"error: refusing non-loopback GUI host {host!r}: "
              f"bind to 127.0.0.1 only", file=sys.stderr)
        return ERROR
    if args.db:
        db_path = Path(args.db).expanduser()
        workdir = db_path.parent
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="ecdat-demo-"))
        db_path = workdir / "demo.db"
    try:
        info = prepare_demo_db(db_path, workdir / "targets")
    except OSError as exc:
        print(f"error: cannot prepare demo workspace: {exc}", file=sys.stderr)
        return ERROR
    try:
        server = make_server(str(db_path), host=host, port=int(args.port))
    except (ValueError, OSError) as exc:
        print(f"error: cannot serve demo GUI: {exc}", file=sys.stderr)
        return ERROR
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    print(f"ECDAT demo (mock) at http://{bound_host}:{bound_port}")
    print(f"Demo workspace: {workdir} (scan ids: {', '.join(info['scan_ids'])})")
    print("Workflow:")
    for step in WORKFLOW:
        print(f"  {step}")
    print("Mock/simulated data only. Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

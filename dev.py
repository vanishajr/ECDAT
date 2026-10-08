"""One-command local startup: ECDAT API + React dashboard in a single terminal.

Usage:
    python dev.py [--port 8734] [--db .ecdat.db] [--no-install] [--api-only] [--web-only]

Runs the loopback API (default http://127.0.0.1:8734) and `npm run dev`
(Vite at http://localhost:5173, proxying /api to the backend) together,
prefixing each line with [api] / [web]. Ctrl-C stops both.

Stdlib only. If frontend/node_modules is missing, `npm install` runs
automatically unless --no-install is given.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
DEFAULT_PORT = 8734


def _npm() -> str:
    exe = shutil.which("npm")
    if exe:
        return exe
    # Windows fallback: shutil.which honors PATHEXT, but be explicit anyway.
    for cand in ("npm.cmd", "npm.exe"):
        found = shutil.which(cand)
        if found:
            return found
    sys.exit("error: npm not found on PATH (need Node.js 18+).")


def _ensure_frontend_deps(npm_exe: str, allow_install: bool) -> None:
    if not (FRONTEND / "package.json").is_file():
        sys.exit("error: frontend/package.json not found; run from the repo root.")
    if (FRONTEND / "node_modules").is_dir():
        return
    if not allow_install:
        sys.exit("error: frontend/node_modules missing; run `cd frontend && npm install` first (or drop --no-install).")
    print("[dev] frontend/node_modules missing; running `npm install` ...", flush=True)
    rc = subprocess.run([npm_exe, "install"], cwd=FRONTEND).returncode
    if rc != 0:
        sys.exit(f"error: `npm install` failed (exit {rc}).")


def _stream(prefix: str, pipe) -> None:
    for line in iter(pipe.readline, ""):
        print(f"{prefix} {line}", end="", flush=True)
    pipe.close()


def _spawn(label: str, cmd: list[str], cwd: Path) -> subprocess.Popen:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    threading.Thread(target=_stream, args=(label, proc.stdout), daemon=True).start()
    return proc


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the ECDAT API + dashboard together.")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="API port (default 8734; custom ports need a matching Vite proxy, so prefer --api-only + manual `npm run dev` for those).")
    ap.add_argument("--db", default=".ecdat.db", help="Shared scan database path.")
    ap.add_argument("--no-install", action="store_true", help="Do not auto-run `npm install` when node_modules is missing.")
    ap.add_argument("--api-only", action="store_true", help="Run only the API server.")
    ap.add_argument("--web-only", action="store_true", help="Run only the Vite dashboard.")
    args = ap.parse_args()

    if args.api_only and args.web_only:
        ap.error("--api-only and --web-only are mutually exclusive.")

    procs: list[subprocess.Popen] = []
    try:
        if not args.web_only:
            procs.append(_spawn(
                "[api]",
                [sys.executable, "-m", "ecdat.cli", "gui",
                 "--port", str(args.port), "--db", args.db],
                ROOT,
            ))
        if not args.api_only:
            npm_exe = _npm()
            _ensure_frontend_deps(npm_exe, allow_install=not args.no_install)
            procs.append(_spawn("[web]", [npm_exe, "run", "dev"], FRONTEND))
        print(f"[dev] API -> http://127.0.0.1:{args.port} | dashboard -> http://localhost:5173 (Ctrl-C to stop)", flush=True)
        for proc in procs:
            proc.wait()
        return max((p.returncode or 0) for p in procs) if procs else 0
    except KeyboardInterrupt:
        print("\n[dev] stopping ...", flush=True)
        return 0
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())

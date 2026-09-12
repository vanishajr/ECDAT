"""ecdat gui [--db PATH] [--host 127.0.0.1] [--port PORT].

Launch the mock-first localhost GUI dashboard. Thin launcher only:
parser/dispatch lives in ecdat.cli, use cases in ecdat.gui.service,
HTTP/routing in ecdat.gui.server.

Loopback only: any --host outside 127.0.0.1/localhost/::1 is refused
with exit 1 before binding. Port 0 lets the OS pick an ephemeral
port (used by tests). Exit 0 on clean shutdown (Ctrl-C), 1 on bind
or serving errors. No new dependencies.
"""

from __future__ import annotations

import argparse
import sys

from ecdat.commands import ERROR
from ecdat.gui.server import LOOPBACK_HOSTS, make_server

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8734


def run(args: argparse.Namespace) -> int:
    host = str(args.host)
    port = int(args.port)
    if host not in LOOPBACK_HOSTS:
        print(
            "error: refusing non-loopback GUI host "
            f"{host!r}: bind to 127.0.0.1 only",
            file=sys.stderr,
        )
        return ERROR
    try:
        server = make_server(args.db, host=host, port=port)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ERROR
    except OSError as exc:
        print(f"error: cannot serve GUI: {exc}", file=sys.stderr)
        return ERROR
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    print(f"Serving ECDAT GUI (mock) at http://{bound_host}:{bound_port}")
    print("Press Ctrl-C to stop. Localhost only; mock/simulated data.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

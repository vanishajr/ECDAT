"""Launch the localhost API consumed by the new React ECDAT interface."""

from __future__ import annotations

import argparse
import sys

from ecdat.commands import ERROR
from ecdat.web.server import LOOPBACK_HOSTS, make_server

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
        server = make_server(host=host, port=port)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ERROR
    except OSError as exc:
        print(f"error: cannot serve GUI: {exc}", file=sys.stderr)
        return ERROR
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    print(f"ECDAT API listening at http://{bound_host}:{bound_port}")
    print("Start the React interface with: cd frontend; npm.cmd run dev")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

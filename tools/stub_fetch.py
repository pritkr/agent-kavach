#!/usr/bin/env python3
"""Hermetic fetch target for evals: serves a fixed HTML page on loopback.

Used by `make eval` so the fetch-parse task never depends on the internet:
    python3 tools/stub_fetch.py [--port 8899]
"""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

BODY = b"<html><head><title>Kavach Test</title></head><body>kavach eval stub</body></html>"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):  # quiet
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    args = ap.parse_args()
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

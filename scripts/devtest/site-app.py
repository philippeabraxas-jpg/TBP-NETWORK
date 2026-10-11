#!/usr/bin/env python3
"""site-app.py — the "application" on machine M2 of the DEV-TEST site (deploy/dev-test/site.md).

A deliberately tiny business service, standing in for whatever an integrator protects. It does what
deploy/integration-contract.md asks of an application: it asks the local `pepd` BEFORE it does anything, and acts
only when pepd answers `forwarded: true`. In monitor mode pepd forwards even a deny (it only logs), in closed mode it
does not, and after a restart it answers "refused" until a quorum reconfirms a posture — the application needs no
other logic for any of this: it follows `forwarded`.

    GET|POST /<action>/<resource>     header  X-TBP-Token: <token, base64>
    GET      /healthz

It never logs a token. If pepd cannot be reached it refuses (503): no verdict, no action.

Environment: APP_LISTEN (host:port, default 127.0.0.1:9000), PEPD_URL (default http://127.0.0.1:8443).
Python 3 standard library only.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PEPD_URL = os.environ.get("PEPD_URL", "http://127.0.0.1:8443").rstrip("/")
LISTEN = os.environ.get("APP_LISTEN", "127.0.0.1:9000")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_TOKEN = 4096


class Handler(BaseHTTPRequestHandler):
    server_version = "tbp-devtest-app"

    def log_message(self, fmt, *args):  # never log the token (it is in a header, but be explicit)
        sys.stderr.write("app: %s %s\n" % (self.command, self.path.split("?")[0]))

    def reply(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def handle_any(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.reply(200, {"ok": True})
        parts = path.strip("/").split("/")
        if len(parts) != 2 or not NAME.match(parts[0]) or not NAME.match(parts[1]):
            return self.reply(400, {"refused": True, "why": "path must be /<action>/<resource>"})
        action, resource = parts
        token = self.headers.get("X-TBP-Token", "")
        if not token or len(token) > MAX_TOKEN:
            return self.reply(401, {"refused": True, "why": "no token (header X-TBP-Token)"})

        req = urllib.request.Request(
            PEPD_URL + "/v1/evaluate",
            data=json.dumps({"token": token, "action": action, "resource": resource}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                verdict = json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError) as err:
            return self.reply(503, {"refused": True, "why": "pepd gave no verdict: %s" % type(err).__name__})

        if verdict.get("forwarded") is True:
            return self.reply(200, {"executed": "%s %s" % (action, resource), "verdict": verdict})
        return self.reply(403, {"refused": True, "verdict": verdict})

    do_GET = handle_any
    do_POST = handle_any


def main():
    host, _, port = LISTEN.rpartition(":")
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    sys.stderr.write("app: listening on %s, asking pepd at %s\n" % (LISTEN, PEPD_URL))
    server.serve_forever()


if __name__ == "__main__":
    main()

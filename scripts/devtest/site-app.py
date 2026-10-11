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

Test trace (issue #329): with APP_TRACE_FILE set, one JSON line per step is appended to that file (0600): the request as
received (who called, which action and resource, whether a token came with it), pepd's verdict as it was returned to
this application, and what the application did with it. The correlation id is the header X-TBP-Trace-Id when the caller
sent one. pepd itself is not touched: the verdict is the one it answered to this application.

Environment: APP_LISTEN (host:port, default 127.0.0.1:9000), PEPD_URL (default http://127.0.0.1:8443),
APP_TRACE_FILE (optional).
Python 3 standard library only.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PEPD_URL = os.environ.get("PEPD_URL", "http://127.0.0.1:8443").rstrip("/")
LISTEN = os.environ.get("APP_LISTEN", "127.0.0.1:9000")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_TOKEN = 4096
TRACE_FILE = os.environ.get("APP_TRACE_FILE", "")
TRACE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def trace(trace_id, component, stage, outcome, **fields):
    """Append one event to the test trace. Never raises: a trace that fails must not change what the app does."""
    if not TRACE_FILE:
        return
    now = time.time()
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%06dZ" % int((now % 1) * 1e6)
    event = {"ts": ts, "component": component, "stage": stage, "outcome": outcome}
    if trace_id:
        event["trace_id"] = trace_id
    for key, value in fields.items():
        if value not in (None, ""):
            event[key] = value if not isinstance(value, str) else re.sub(r"[\x00-\x1f\x7f]", "?", value)[:256]
    try:
        fd = os.open(TRACE_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, (json.dumps(event) + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass


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
        t_start = time.perf_counter()  # durations are measured here, on this machine, with this clock
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.reply(200, {"ok": True})
        parts = path.strip("/").split("/")
        if len(parts) != 2 or not NAME.match(parts[0]) or not NAME.match(parts[1]):
            return self.reply(400, {"refused": True, "why": "path must be /<action>/<resource>"})
        action, resource = parts
        token = self.headers.get("X-TBP-Token", "")
        tid = self.headers.get("X-TBP-Trace-Id", "")
        tid = tid if TRACE_ID.match(tid) else ""
        peer = self.client_address[0]
        subject = "%s %s" % (action, resource)
        trace(tid, "app", "request", "received", intent=subject, peer=peer,
              detail="with a token" if token else "without a token")
        if not token or len(token) > MAX_TOKEN:
            trace(tid, "app", "outcome", "refused", reason="no-token", intent=subject, peer=peer, detail="401")
            return self.reply(401, {"refused": True, "why": "no token (header X-TBP-Token)"})

        req = urllib.request.Request(
            PEPD_URL + "/v1/evaluate",
            data=json.dumps({"token": token, "action": action, "resource": resource}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        t_pepd = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                verdict = json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError) as err:
            trace(tid, "app", "outcome", "refused", reason="pepd-no-verdict", intent=subject, peer=peer,
                  detail="503 " + type(err).__name__)
            return self.reply(503, {"refused": True, "why": "pepd gave no verdict: %s" % type(err).__name__})

        rtt_us = int((time.perf_counter() - t_pepd) * 1e6)
        trace(tid, "pepd", "verdict", "allow" if verdict.get("allow") else "deny", reason=verdict.get("reason"),
              intent=subject, mode=verdict.get("mode"), forwarded=verdict.get("forwarded"),
              elapsed_us=verdict.get("elapsed_us"), rtt_us=rtt_us, detail="verdict as returned to the application")
        app_us = int((time.perf_counter() - t_start) * 1e6)
        if verdict.get("forwarded") is True:
            trace(tid, "app", "outcome", "executed", intent=subject, peer=peer, detail="200", app_us=app_us)
            return self.reply(200, {"executed": "%s %s" % (action, resource), "verdict": verdict})
        trace(tid, "app", "outcome", "refused", reason="not-forwarded", intent=subject, peer=peer, detail="403", app_us=app_us)
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

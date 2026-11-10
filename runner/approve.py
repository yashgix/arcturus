"""Approve a grant, or register a passkey, on a small local web page (Touch ID on the Mac, Face ID on the iPhone).

  python3 runner/approve.py RUN                  # opens RUN's grant in Safari; approve it with a passkey
  python3 runner/approve.py --register           # creates a passkey for localhost, then prints the sudo command
  python3 runner/approve.py --register --tailnet # the same for https://<mac>.<tailnet>.ts.net (the iPhone)

Listens on both loopback addresses only and stops after one approval or after --minutes. The links it prints hold
a one-time secret, so other local programs cannot use the page. When a passkey is trusted for the Mac's tailnet name,
`tailscale serve` (tailnet only, never Funnel) forwards that name to the page while it is open.
"""

import argparse
import hashlib
from contextlib import contextmanager
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import urllib.request

import grant as grants
import passkey

CHALLENGE_SECONDS = 300
MAX_CHALLENGES = 20
MAX_BODY = 16384
SAFARI = ["/usr/bin/open", "-a", "Safari"]
TAILSCALE = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
# The app's bundled CLI starts as the GUI, and fails, unless it sees a shell (SHLVL).
TAILSCALE_ENV = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "SHLVL": "1"}
SCRIPT = (Path(__file__).resolve().parent / "approve.js").read_bytes()
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; connect-src 'self'; "
    "style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}
PAGE = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Arcturus</title><body style="font:17px/1.5 -apple-system,sans-serif;max-width:40em;margin:2em auto;padding:0 1em">
{body}<p><button id="go" style="font-size:1.1em;padding:.6em 1.2em">{button}</button></p><p id="status"></p>
<script src="approve.js"></script></body></html>"""


class Page:
    """State shared by both loopback listeners: one-time challenges, the secret link and the single result."""

    def __init__(self, origins):
        for origin in origins:
            passkey.rp_id(origin)
        self.origins = {urlsplit(origin).netloc: origin for origin in origins}
        self.token = secrets.token_urlsafe(18)
        self.nonces, self.lock, self.result, self.done, self.servers = {}, threading.Lock(), None, threading.Event(), []

    def link(self, origin):
        return f"{origin}/{self.token}/"

    def listen(self, port):
        """Hold the port on 127.0.0.1 and ::1, so no other program can answer for localhost while the page is open."""
        servers = []
        try:
            servers.append(Server(("127.0.0.1", port), self))
            servers.append(Server6(("::1", port), self))
        except OSError:
            for server in servers:
                server.server_close()
            raise
        self.servers = servers
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()

    def issue(self):
        nonce = secrets.token_bytes(32)
        with self.lock:
            self.nonces = {n: t for n, t in self.nonces.items() if t > time.time()}
            if len(self.nonces) >= MAX_CHALLENGES:
                raise ValueError("too many open challenges; wait a few minutes")
            self.nonces[nonce] = time.time() + CHALLENGE_SECONDS
        return nonce

    def finish(self, body, origin):
        """Each challenge works once, within five minutes; the first valid answer wins and closes the page."""
        nonce = passkey.unb64(body.pop("nonce", None))
        with self.lock:
            if self.result is not None or self.nonces.pop(nonce, 0) < time.time():
                raise ValueError("challenge expired or already used; reload the page")
            self.result = self.complete(body, nonce, origin)
        self.done.set()
        return self.message()


class GrantPage(Page):
    def __init__(self, origins, run):
        super().__init__(origins)
        self.run, self.grant = run, json.loads((run / "grant.json").read_text())
        self.digest = grants.digest(self.grant)
        trusted = passkey.credentials()
        self.allowed = {o: [r["credential_id"] for r in trusted if r["origin"] == o] for o in origins}
        if not origins or not all(self.allowed.values()):
            raise ValueError(f"no trusted passkey for {', '.join(origins) or 'this page'}; register one first")
        if os.path.lexists(run / grants.APPROVAL):
            raise ValueError(
                f"{run / grants.APPROVAL} exists; if the runner does not accept it, delete it and approve again"
            )
        if self.grant["enforcement_sha256"] != grants.enforcement_sha256():
            raise ValueError("enforcement code changed since the grant was drafted")
        if time.time() >= self.grant["expires_at"]:
            raise ValueError("grant expired")

    def html(self, origin):
        terms = escape(json.dumps(self.grant, indent=2, sort_keys=True))
        return PAGE.format(
            button="Approve with Touch ID or Face ID",
            body=(
                f"<h1>Approve this grant?</h1><p><b>{escape(grants.describe(self.grant))}</b></p>"
                f"<details open><summary>Exact terms (digest {self.digest[:16]}…)</summary><pre>{terms}</pre></details>"
            ),
        )

    def options(self, origin):
        nonce = self.issue()
        return {
            "mode": "approve",
            "nonce": passkey.b64(nonce),
            "rpId": passkey.rp_id(origin),
            "allow": self.allowed[origin],
            "challenge": passkey.b64(passkey.challenge(self.digest, nonce)),
        }

    def complete(self, body, nonce, origin):
        if body.get("credential_id") not in self.allowed[origin]:
            raise ValueError("this passkey belongs to the other link")
        body["nonce"] = passkey.b64(nonce)
        grants.approve(self.run, self.grant, body)
        return body

    def message(self):
        return "Approved. You can close this page."


class RegisterPage(Page):
    def html(self, origin):
        return PAGE.format(
            body=f"<h1>Register a passkey for Arcturus</h1><p>Site: {escape(passkey.rp_id(origin))}</p>",
            button="Create passkey",
        )

    def options(self, origin):
        nonce = self.issue()
        # One user id per origin, so registering for another port or name never replaces this passkey.
        user = passkey.b64(hashlib.sha256(origin.encode()).digest()[:16])
        return {
            "mode": "register",
            "nonce": passkey.b64(nonce),
            "challenge": passkey.b64(nonce),
            "rp": {"id": passkey.rp_id(origin), "name": "Arcturus"},
            "user": {"id": user, "name": f"arcturus@{urlsplit(origin).netloc}", "displayName": "Arcturus"},
        }

    def complete(self, body, nonce, origin):
        return passkey.registration(body, nonce, origin)

    def message(self):
        return (
            f"Passkey created. Fingerprint {passkey.fingerprint(self.result)}. Run the sudo command in Terminal "
            "only if it shows this same fingerprint."
        )


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, page):
        self.page = page
        super().__init__(address, Handler)


class Server6(Server):
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    timeout = 10

    def do_GET(self):
        page, found = self.server.page, self.route()
        if found is None:
            return
        origin, route = found
        routes = {
            "": ("text/html; charset=utf-8", lambda: page.html(origin).encode()),
            "approve.js": ("text/javascript", lambda: SCRIPT),
            "options": ("application/json", lambda: json.dumps(page.options(origin)).encode()),
        }
        if route not in routes:
            return self.send(404, "text/plain", b"not found")
        kind, content = routes[route]
        try:
            self.send(200, kind, content())
        except ValueError as exc:
            self.send(429, "text/plain", str(exc).encode())

    def do_POST(self):
        found = self.route()
        if found is None:
            return
        origin, route = found
        if route != "done":
            return self.send(404, "text/plain", b"not found")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if self.headers.get("Origin") != origin or not 0 < length <= MAX_BODY:
            return self.send(400, "text/plain", b"bad request")
        try:
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("bad request")
            message = self.server.page.finish(body, origin)
        except (ValueError, OSError) as exc:
            return self.send(400, "text/plain", f"Not approved: {exc}".encode())
        self.send(200, "text/plain", message.encode())

    def route(self):
        """(origin, path after the secret), or None (after answering) for a wrong host or secret."""
        page = self.server.page
        # The Host check stops a rebound DNS name from reading the page.
        origin = page.origins.get(self.headers.get("Host"))
        if origin is None:
            self.send(403, "text/plain", b"wrong host")
            return None
        prefix = f"/{page.token}/"
        if not self.path.startswith(prefix):
            self.send(404, "text/plain", b"not found")
            return None
        return origin, self.path[len(prefix) :]

    def send(self, status, kind, content):
        self.send_response(status)
        for name, value in {**HEADERS, "Content-Type": kind, "Content-Length": str(len(content))}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *args):
        pass


def tailscale(*args):
    """Output of the Tailscale app's CLI, or None if it fails."""
    try:
        return subprocess.run(
            [TAILSCALE, *args], env=TAILSCALE_ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=True
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None


def tailnet_origin():
    """https://<mac>.<tailnet>.ts.net while Tailscale is connected, else None."""
    try:
        status = json.loads(tailscale("status", "--json"))
        name = status["Self"]["DNSName"].rstrip(".")
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    return f"https://{name}" if status.get("BackendState") == "Running" and name else None


def serving(host):
    """True unless Tailscale surely serves nothing on HOST now. Never take over another serve setting, nor a
    leftover foreground `tailscale serve` from a killed runner (`serve status` does not list those)."""
    try:
        if json.loads(tailscale("serve", "status", "--json")) != {}:
            return True
        socket.create_connection((host, 443), timeout=3).close()
    except ConnectionRefusedError:
        return False
    except (ValueError, TypeError, OSError):
        pass
    return True


def grant_origins(port):
    """localhost for the Mac, then the tailnet name for the phone, each only if a passkey is trusted for it."""
    trusted = {r["origin"] for r in passkey.credentials()}
    origins = [o for o in (f"http://localhost:{port}",) if o in trusted]
    if any(o.startswith("https://") for o in trusted):
        tailnet = tailnet_origin()
        if tailnet in trusted:
            origins.append(tailnet)
        elif not origins:
            raise ValueError("Tailscale is not connected, and no passkey is trusted for localhost")
    return origins


def reachable(link, proxy, seconds=60):
    """True once the page answers through the proxy; the first HTTPS certificate can take half a minute."""
    deadline = time.time() + seconds
    while time.time() < deadline and proxy.poll() is None:
        try:
            with urllib.request.urlopen(link + "approve.js", timeout=10) as reply:
                return reply.read() == SCRIPT
        except OSError:
            time.sleep(1)
    return False


@contextmanager
def tailnet_proxy(page, port):
    """While the page is open, `tailscale serve` forwards the Mac's tailnet name to it (tailnet only).

    Yields a check of the iPhone link (None if it works, else why not), or None when there is no iPhone link."""
    remote = [o for o in page.origins.values() if o.startswith("https://")]
    if not remote:
        yield None
        return
    if serving(urlsplit(remote[0]).hostname):
        print(
            "WARNING: Tailscale already serves something on this Mac (`tailscale serve status`, or a leftover "
            "`tailscale serve` process), or does not answer; no iPhone link this time.",
            flush=True,
        )
        yield None
        return
    # A plain kill must still run the cleanup below, or `tailscale serve` outlives the page.
    previous, proxy = signal.signal(signal.SIGTERM, lambda *_: sys.exit(143)), None

    def problem():
        if reachable(page.link(remote[0]), proxy):
            return None
        return proxy.stderr.read().decode(errors="replace").strip()[:300] if proxy.poll() is not None else "no answer"

    try:
        proxy = subprocess.Popen(
            [TAILSCALE, "serve", "--bg=false", f"http://127.0.0.1:{port}"],
            env=TAILSCALE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        yield problem
    finally:
        if proxy:
            stop(proxy)
        signal.signal(signal.SIGTERM, previous)


def stop(proxy):
    proxy.terminate()
    try:
        proxy.wait(10)
    except subprocess.TimeoutExpired:
        proxy.kill()


def open_in_safari(link):
    """Safari, not the default browser: the passkeys live in Safari's iCloud Keychain."""
    try:
        subprocess.run(SAFARI + [link], stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=True)
    except (OSError, subprocess.SubprocessError):
        print("Could not open Safari; open the link above by hand.", flush=True)


def show(page, port, minutes):
    """Serve the page, open it in Safari and wait for one answer; True if it got one."""
    page.listen(port)
    try:
        with tailnet_proxy(page, port) as phone_problem:
            links = [page.link(origin) for origin in page.origins.values()]
            for link in links:
                print(f"Open on the {'iPhone (or Mac)' if link.startswith('https://') else 'Mac'}: {link}", flush=True)
            print(f"The page closes after one use or {minutes:g} minutes.", flush=True)
            mac = links[0].startswith("http://")
            if mac:
                open_in_safari(links[0])
            problem = phone_problem and phone_problem()
            if problem:
                print(f"WARNING: the iPhone link does not work ({problem}); use the Mac.", flush=True)
            if not mac:
                open_in_safari(links[0])
            page.done.wait(minutes * 60)
    finally:
        page.close()
    return page.result is not None


def ensure(run, port=8765, minutes=15):
    """Return once RUN's grant is approved, asking in Safari first if it is not yet: the tap is the go."""
    try:
        grants.verified(run)
    except grants.GrantError:
        if not show(GrantPage(grant_origins(port), Path(run)), port, minutes):
            raise grants.GrantError("stopped without approval") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run", type=Path, nargs="?")
    parser.add_argument("--register", action="store_true")
    parser.add_argument("--tailnet", action="store_true", help="register for the Mac's tailnet name")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--minutes", type=float, default=15)
    args = parser.parse_args(argv)
    if bool(args.run) == args.register or (args.tailnet and not args.register):
        parser.error("give a run folder, or --register (optionally with --tailnet)")
    try:
        if args.run:
            page = GrantPage(grant_origins(args.port), args.run)
        else:
            origin = tailnet_origin() if args.tailnet else f"http://localhost:{args.port}"
            if origin is None:
                raise ValueError("Tailscale is not connected")
            page = RegisterPage([origin])
        if not show(page, args.port, args.minutes):
            print("Stopped without approval.", file=sys.stderr)
            return 1
    except (ValueError, OSError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1
    if args.run:
        print(f"APPROVED {grants.describe(page.grant)}")
    else:
        print(
            f"Passkey fingerprint {passkey.fingerprint(page.result)}. Compare it with the page, then run:\n"
            f"{passkey.install_command(page.result)}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

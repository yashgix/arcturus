from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))

import approve
import grant as grants
from grant_fixture import sign, signed_root
import passkey
from passkey import b64

ORIGIN = "http://localhost:8765"


def openssl(*args, data=None):
    return subprocess.run(["/usr/bin/openssl", *args], input=data, capture_output=True, check=True).stdout


class SoftPasskey:
    """A software authenticator: a real P-256 key, signing what a browser would send."""

    def __init__(self, folder, origin=ORIGIN, curve="prime256v1"):
        self.key = Path(folder) / f"passkey-{secrets.token_hex(4)}.pem"
        openssl("ecparam", "-name", curve, "-genkey", "-noout", "-out", str(self.key))
        self.spki = openssl("ec", "-in", str(self.key), "-pubout", "-outform", "DER")
        self.credential_id, self.origin = secrets.token_bytes(16), origin

    def record(self):
        return {
            "credential_id": b64(self.credential_id),
            "public_key": b64(self.spki),
            "origin": self.origin,
            "registered": 1,
        }

    def authenticator_data(self, flags=0x05, site=None):
        return hashlib.sha256((site or passkey.rp_id(self.origin)).encode()).digest() + bytes([flags]) + bytes(4)

    def client_data(self, kind, expected, **fields):
        return json.dumps(
            {"type": kind, "challenge": b64(expected), "origin": self.origin, "crossOrigin": False, **fields}
        ).encode()

    def sign(self, authenticator, client):
        return openssl("dgst", "-sha256", "-sign", str(self.key), data=authenticator + hashlib.sha256(client).digest())

    def get(self, digest, nonce=None, client=None, authenticator=None):
        nonce = nonce or secrets.token_bytes(32)
        client = client or self.client_data("webauthn.get", passkey.challenge(digest, nonce))
        authenticator = authenticator or self.authenticator_data()
        return {
            "credential_id": b64(self.credential_id),
            "nonce": b64(nonce),
            "client_data": b64(client),
            "authenticator_data": b64(authenticator),
            "signature": b64(self.sign(authenticator, client)),
        }

    def create(self, nonce, flags=0x45, kind="webauthn.create"):
        return {
            "credential_id": b64(self.credential_id),
            "client_data": b64(self.client_data(kind, nonce)),
            "authenticator_data": b64(self.authenticator_data(flags)),
            "public_key": b64(self.spki),
            "algorithm": passkey.ES256,
        }


def folder(test):
    temporary = tempfile.TemporaryDirectory()
    test.addCleanup(temporary.cleanup)
    return Path(temporary.name).resolve()


def trust(test, records):
    """Trust whatever records() returns at call time, for the rest of the test."""
    patcher = patch.object(passkey, "credentials", records)
    patcher.start()
    test.addCleanup(patcher.stop)


def changed(approval, field, edit):
    return {**approval, field: b64(edit(passkey.unb64(approval[field])))}


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Verify(unittest.TestCase):
    def setUp(self):
        self.root = folder(self)
        self.key = SoftPasskey(self.root)
        trust(self, lambda: [self.key.record()])
        self.digest = hashlib.sha256(b"grant").hexdigest()

    def test_accepts_exact_approval(self):
        self.assertEqual(passkey.verify(self.digest, self.key.get(self.digest)), self.key.record())

    def test_refuses_every_tampering(self):
        key, digest, good = self.key, self.digest, self.key.get(self.digest)
        nonce = secrets.token_bytes(32)
        expected = passkey.challenge(digest, nonce)
        other = SoftPasskey(self.root)
        cases = {
            "other grant": key.get(hashlib.sha256(b"other").hexdigest()),
            "nonce swapped": {**good, "nonce": b64(secrets.token_bytes(32))},
            "other origin": key.get(
                digest, nonce, key.client_data("webauthn.get", expected, origin="http://localhost:9999")
            ),
            "creation type": key.get(digest, nonce, key.client_data("webauthn.create", expected)),
            "cross origin": key.get(digest, nonce, key.client_data("webauthn.get", expected, crossOrigin=True)),
            "top origin": key.get(digest, nonce, key.client_data("webauthn.get", expected, topOrigin=ORIGIN)),
            "other site": key.get(digest, authenticator=key.authenticator_data(site="example.com")),
            "no verification": key.get(digest, authenticator=key.authenticator_data(flags=0x01)),
            "no presence": key.get(digest, authenticator=key.authenticator_data(flags=0x04)),
            "unknown passkey": other.get(digest),
            "other key, same id": {**other.get(digest), "credential_id": good["credential_id"]},
            "signature changed": changed(good, "signature", lambda s: s[:-1] + bytes([s[-1] ^ 1])),
            "authenticator data changed": changed(good, "authenticator_data", lambda a: a[:-1] + b"\x01"),
            "client data changed": changed(good, "client_data", lambda c: c[:-1] + b',"x":1}'),
            "short nonce": key.get(digest, secrets.token_bytes(8)),
            "extra field": {**good, "extra": "x"},
            "missing field": {k: v for k, v in good.items() if k != "signature"},
            "bad base64": {**good, "signature": good["signature"] + "!"},
            "id not a string": {**good, "credential_id": [good["credential_id"]]},
            "not a dict": [good],
        }
        for name, approval in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                passkey.verify(digest, approval)

    def test_trusts_only_p256_records_on_allowed_origins(self):
        p384 = SoftPasskey(self.root, curve="secp384r1").record()
        good = self.key.record()
        for record in (
            p384,
            {**good, "origin": "http://my-mac.example.ts.net"},
            {**good, "registered": "1"},
            {**good, "label": "x"},
        ):
            with self.subTest(record=record), self.assertRaises(ValueError):
                passkey.check_record(record)

    def test_origins(self):
        self.assertEqual(passkey.rp_id("https://my-mac.tail1.ts.net"), "my-mac.tail1.ts.net")
        self.assertEqual(passkey.rp_id(ORIGIN), "localhost")
        for origin in (
            "http://my-mac.tail1.ts.net",
            "https://a.ts.net/",
            "https://a.ts.net/x",
            "https://u@a.ts.net",
            "file:///x",
            None,
        ):
            with self.subTest(origin), self.assertRaises(ValueError):
                passkey.rp_id(origin)


class TrustStore(unittest.TestCase):
    def test_must_be_root_owned_folder_and_files(self):
        root = folder(self)
        store, record = root / "passkeys", SoftPasskey(root).record()
        with patch.object(passkey, "TRUST", store):
            self.assertEqual(passkey.credentials(), [])
            store.mkdir()
            (store / "key.json").write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "unsafe"):
                passkey.credentials()
            checked = []
            with patch.object(passkey.operator_approval, "root_owned", lambda *a, **k: checked.append(a[0])):
                self.assertEqual(passkey.credentials(), [record])
            self.assertEqual(checked, [store, store / "key.json"])

    def test_install_command_writes_exactly_the_record_once(self):
        root = folder(self)
        record, store = SoftPasskey(root).record(), root / "passkeys"
        with patch.object(passkey, "TRUST", store):
            command = passkey.install_command(record)
        self.assertTrue(command.startswith("/usr/bin/sudo -k /bin/sh -c '"))
        shell = command.removeprefix("/usr/bin/sudo -k ")
        run = lambda: subprocess.run(shell, shell=True, capture_output=True, text=True)
        self.assertEqual(run().returncode, 0)
        self.assertEqual(json.loads((store / f"{passkey.fingerprint(record)}.json").read_text()), record)
        self.assertNotEqual(run().returncode, 0)


class Registration(unittest.TestCase):
    def setUp(self):
        self.key = SoftPasskey(folder(self))
        self.nonce = secrets.token_bytes(32)

    def test_accepts_creation_for_this_page(self):
        record = passkey.registration(self.key.create(self.nonce), self.nonce, ORIGIN)
        self.assertEqual({**record, "registered": 1}, self.key.record())

    def test_refuses_creation_for_another_request(self):
        good = self.key.create(self.nonce)
        cases = {
            "assertion type": self.key.create(self.nonce, kind="webauthn.get"),
            "no verification": self.key.create(self.nonce, flags=0x41),
            "no attested data flag": self.key.create(self.nonce, flags=0x05),
            "other challenge": self.key.create(secrets.token_bytes(32)),
            "RS256": {**good, "algorithm": -257},
        }
        for name, response in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                passkey.registration(response, self.nonce, ORIGIN)


class Grants(unittest.TestCase):
    def setUp(self):
        self.root = signed_root(self)
        self.key = SoftPasskey(self.root)
        self.records = [self.key.record()]
        trust(self, lambda: self.records)
        self.run = self.root / "run"
        self.run.mkdir()
        self.grant = grants.draft(
            "build",
            {"companies": ["x'; /usr/bin/id; echo '"], "company_ids": ["c1"], "operations": ["build"]},
            {"deepseek-flash": {}},
            2.5,
            60,
            1,
        )
        grants.write(self.run, self.grant)

    def approve(self):
        grants.approve(self.run, self.grant, self.key.get(grants.digest(self.grant)))

    def test_plain_words_name_enforced_scope_and_are_quoted_for_the_root_shell(self):
        summary = grants.describe(self.grant)
        self.assertIn("(ids c1) (operations build)", summary)
        self.assertIn(f"echo {shlex.quote(summary)}\n", (self.run / "sign-grant.sh").read_text())

    def test_store_refuses_an_approval_of_another_grant(self):
        with self.assertRaises(ValueError):
            grants.approve(self.run, self.grant, self.key.get(hashlib.sha256(b"other").hexdigest()))
        self.assertFalse((self.run / grants.APPROVAL).exists())

    def test_either_valid_proof_is_enough_and_junk_never_is(self):
        (self.run / grants.APPROVAL).write_text(json.dumps(self.key.get(hashlib.sha256(b"other").hexdigest())))
        with self.assertRaisesRegex(grants.GrantError, "passkey approval: .*signature: "):
            grants.verified(self.run)
        sign(self, self.grant)
        self.assertEqual(grants.verified(self.run), self.grant)

    def test_revoked_passkey_voids_its_approvals(self):
        self.approve()
        self.assertEqual(grants.verified(self.run), self.grant)
        self.records = []
        with self.assertRaises(grants.GrantError):
            grants.verified(self.run)

    def test_redrafting_removes_an_old_approval(self):
        self.approve()
        grants.write(self.run, self.grant)
        self.assertFalse((self.run / grants.APPROVAL).exists())


class PageCase(unittest.TestCase):
    """A served grant page and a client that speaks to it like Safari would."""

    def setUp(self):
        self.root = folder(self)
        self.key = SoftPasskey(self.root)
        trust(self, lambda: [self.key.record()])
        self.run = self.root / "run"
        self.run.mkdir()
        scope = {"companies": ["<script>alert(1)</script>"], "company_ids": ["c1"], "operations": ["build"]}
        self.grant = grants.draft("build", scope, {"deepseek-flash": {}}, 2.5, 60, 1)
        self.write_grant(self.grant)

    def write_grant(self, grant):
        (self.run / "grant.json").write_text(json.dumps(grant))

    def serve(self, register=False, more=()):
        self.port = free_port()
        self.key.origin = self.origin = f"http://localhost:{self.port}"
        origins = [self.origin, *more]
        page = approve.RegisterPage(origins) if register else approve.GrantPage(origins, self.run)
        page.listen(self.port)
        self.addCleanup(page.close)
        self.page, self.token = page, page.token
        return page

    def request(self, method, path, body=None, host=None, origin=None, address="127.0.0.1", headers=None):
        connection = http.client.HTTPConnection(address, self.port, timeout=10)
        connection.request(
            method,
            f"/{self.token}/{path}" if path is not None else "/",
            json.dumps(body) if body is not None else None,
            {
                "Host": host or f"localhost:{self.port}",
                "Origin": origin or self.origin,
                "Content-Type": "application/json",
                **(headers or {}),
            },
        )
        response = connection.getresponse()
        return response.status, response.read().decode(), dict(response.getheaders())

    def approval(self, digest=None):
        options = json.loads(self.request("GET", "options")[1])
        return options, self.key.get(digest or grants.digest(self.grant), passkey.unb64(options["nonce"]))


class Page(PageCase):
    def test_page_shows_plain_terms_escaped_and_unframeable(self):
        self.serve()
        status, html, headers = self.request("GET", "")
        self.assertEqual(status, 200)
        self.assertIn("Ceiling $2.50, at most 60 calls", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert", html)
        self.assertIn("<details open>", html)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("GET", "", host="evil.example")[0], 403)

    def test_only_the_secret_link_works(self):
        self.serve()
        self.assertEqual(self.request("GET", None)[0], 404)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", "/options", headers={"Host": f"localhost:{self.port}"})
        self.assertEqual(connection.getresponse().status, 404)
        self.assertEqual(self.request("GET", "grant.json")[0], 404)

    def test_holds_localhost_on_ipv4_and_ipv6(self):
        self.serve()
        self.assertEqual(self.request("GET", "", address="::1")[0], 200)
        port = free_port()
        with socket.socket(socket.AF_INET6) as squatter:
            squatter.bind(("::1", port))
            squatter.listen()
            page = approve.RegisterPage([f"http://localhost:{port}"])
            with self.assertRaises(OSError):
                page.listen(port)

    def test_approval_is_stored_and_accepted_as_the_grant_signature(self):
        page = self.serve()
        options, approval = self.approval()
        self.assertEqual(
            options["challenge"], b64(passkey.challenge(grants.digest(self.grant), passkey.unb64(options["nonce"])))
        )
        self.assertEqual(self.request("POST", "done", approval)[:2], (200, "Approved. You can close this page."))
        self.assertTrue(page.done.is_set())
        self.assertEqual(grants.verified(self.run), self.grant)
        self.write_grant({**self.grant, "ceiling_microusd": 10_000_000})
        with self.assertRaises(grants.GrantError):
            grants.verified(self.run)

    def test_challenges_are_one_time_expire_and_are_capped(self):
        self.serve()
        _, approval = self.approval()
        bad = changed(approval, "signature", lambda s: s[:-1] + bytes([s[-1] ^ 1]))
        self.assertEqual(self.request("POST", "done", bad)[0], 400)
        status, text, _ = self.request("POST", "done", approval)
        self.assertEqual((status, "already used" in text), (400, True))
        with patch.object(approve, "CHALLENGE_SECONDS", -1):
            _, expired = self.approval()
        self.assertEqual(self.request("POST", "done", expired)[0], 400)
        for _ in range(approve.MAX_CHALLENGES):
            self.request("GET", "options")
        self.assertEqual(self.request("GET", "options")[0], 429)
        self.assertFalse((self.run / grants.APPROVAL).exists())

    def test_refuses_other_grant_wrong_origin_and_bad_bodies(self):
        self.serve()
        _, other = self.approval(hashlib.sha256(b"other").hexdigest())
        self.assertEqual(self.request("POST", "done", other)[0], 400)
        _, approval = self.approval()
        self.assertEqual(self.request("POST", "done", approval, origin="http://evil.example")[0], 400)
        self.assertEqual(self.request("POST", "done", {"x": "y" * approve.MAX_BODY})[0], 400)
        self.assertEqual(self.request("POST", "done", approval, headers={"Content-Length": "x"})[0], 400)
        self.assertFalse((self.run / grants.APPROVAL).exists())

    def test_will_not_serve_a_grant_it_cannot_approve(self):
        for grant, reason in (
            ({**self.grant, "expires_at": 1}, "expired"),
            ({**self.grant, "enforcement_sha256": "0" * 64}, "enforcement code changed"),
        ):
            self.write_grant(grant)
            with self.subTest(reason), self.assertRaisesRegex(ValueError, reason):
                self.serve()
        self.write_grant(self.grant)
        (self.run / grants.APPROVAL).write_text("{}")
        with self.assertRaisesRegex(ValueError, "exists; if the runner does not accept it, delete it"):
            self.serve()
        with patch.object(passkey, "credentials", lambda: []), self.assertRaisesRegex(ValueError, "no trusted"):
            approve.GrantPage([ORIGIN], self.run)

    def test_registration_has_one_winner_and_shows_its_full_fingerprint(self):
        page = self.serve(register=True)
        responses = []
        for _ in range(2):
            options = json.loads(self.request("GET", "options")[1])
            self.assertEqual((options["mode"], options["rp"]["id"]), ("register", "localhost"))
            responses.append({**self.key.create(passkey.unb64(options["challenge"])), "nonce": options["nonce"]})
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda r: self.request("POST", "done", r), responses))
        self.assertEqual(sorted(status for status, _, _ in results), [200, 400])
        winner = next(text for status, text, _ in results if status == 200)
        self.assertIn(f"Fingerprint {passkey.fingerprint(page.result)}.", winner)
        self.assertEqual(page.result["public_key"], self.key.record()["public_key"])

    def test_post_to_another_path_is_answered(self):
        self.serve()
        self.assertEqual(self.request("POST", "options", {})[0], 404)


class TwoOrigins(PageCase):
    """The Mac on localhost and the iPhone on the tailnet name, behind `tailscale serve`, share one page."""

    TAILNET = "https://my-mac.example.ts.net"

    def setUp(self):
        super().setUp()
        self.phone = SoftPasskey(self.root, origin=self.TAILNET)
        trust(self, lambda: [self.key.record(), self.phone.record()])

    def serve(self):
        return super().serve(more=[self.TAILNET])

    def phone_request(self, method, path, body=None, origin=TAILNET):
        return self.request(method, path, body, host="my-mac.example.ts.net", origin=origin)

    def test_each_origin_gets_its_own_site_and_passkey(self):
        self.serve()
        mac = json.loads(self.request("GET", "options")[1])
        phone = json.loads(self.phone_request("GET", "options")[1])
        self.assertEqual((mac["rpId"], mac["allow"]), ("localhost", [self.key.record()["credential_id"]]))
        self.assertEqual(
            (phone["rpId"], phone["allow"]), ("my-mac.example.ts.net", [self.phone.record()["credential_id"]])
        )

    def test_phone_approval_through_the_tailnet_name(self):
        self.serve()
        options = json.loads(self.phone_request("GET", "options")[1])
        approval = self.phone.get(grants.digest(self.grant), passkey.unb64(options["nonce"]))
        self.assertEqual(self.phone_request("POST", "done", approval, origin=self.origin)[0], 400)
        self.assertEqual(self.phone_request("POST", "done", approval)[0], 200)
        self.assertEqual(grants.verified(self.run), self.grant)

    def test_a_passkey_works_only_on_its_own_link(self):
        self.serve()
        options = json.loads(self.phone_request("GET", "options")[1])
        mac_key = self.key.get(grants.digest(self.grant), passkey.unb64(options["nonce"]))
        status, text, _ = self.phone_request("POST", "done", mac_key)
        self.assertEqual((status, "other link" in text), (400, True))
        self.assertFalse((self.run / grants.APPROVAL).exists())

    def test_every_origin_needs_a_trusted_passkey(self):
        trust(self, lambda: [self.key.record()])
        with self.assertRaisesRegex(ValueError, "no trusted"):
            approve.GrantPage([ORIGIN, self.TAILNET], self.run)
        with self.assertRaisesRegex(ValueError, "no trusted"):
            approve.GrantPage([], self.run)

    def test_offers_only_origins_with_a_trusted_passkey(self):
        trust(self, lambda: [{**self.key.record(), "origin": "http://localhost:8765"}, self.phone.record()])
        with patch.object(approve, "tailnet_origin", lambda: self.TAILNET):
            self.assertEqual(approve.grant_origins(8765), ["http://localhost:8765", self.TAILNET])
            self.assertEqual(approve.grant_origins(9000), [self.TAILNET])
        with patch.object(approve, "tailnet_origin", lambda: None):
            self.assertEqual(approve.grant_origins(8765), ["http://localhost:8765"])
            with self.assertRaisesRegex(ValueError, "Tailscale is not connected"):
                approve.grant_origins(9000)

    def test_asks_tailscale_only_if_a_tailnet_passkey_is_trusted(self):
        trust(self, lambda: [{**self.key.record(), "origin": "http://localhost:8765"}])
        with patch.object(approve, "tailnet_origin") as tailnet:
            self.assertEqual(approve.grant_origins(8765), ["http://localhost:8765"])
        tailnet.assert_not_called()


class Tailscale(unittest.TestCase):
    TAILNET_PAGE = staticmethod(lambda: approve.RegisterPage(["https://my-mac.tail1.ts.net"]))

    def test_tailnet_origin_only_while_connected(self):
        running = {"BackendState": "Running", "Self": {"DNSName": "my-mac.tail1.ts.net."}}
        cases = {
            json.dumps(running).encode(): "https://my-mac.tail1.ts.net",
            json.dumps({**running, "BackendState": "Stopped"}).encode(): None,
            json.dumps({"BackendState": "Running"}).encode(): None,
            b"not json": None,
            None: None,
        }
        for stdout, expected in cases.items():
            with self.subTest(stdout), patch.object(approve, "tailscale", return_value=stdout):
                self.assertEqual(approve.tailnet_origin(), expected)

    def test_cli_failure_is_none(self):
        failed = subprocess.CalledProcessError(1, [])
        with patch.object(approve.subprocess, "run", side_effect=failed) as run:
            self.assertIsNone(approve.tailscale("status"))
        self.assertEqual(run.call_args.kwargs["env"]["SHLVL"], "1")

    def test_serving_unless_surely_empty(self):
        refused, answers, timeout = ConnectionRefusedError(), Mock(), TimeoutError()
        for stdout, connect, expected in (
            (b'{"TCP": {"443": {}}}', refused, True),
            (b"x", refused, True),
            (None, refused, True),
            (b"{}", answers, True),
            (b"{}", timeout, True),
            (b"{}", refused, False),
        ):
            with (
                self.subTest(stdout=stdout, connect=connect),
                patch.object(approve, "tailscale", return_value=stdout),
                patch.object(approve.socket, "create_connection", side_effect=[connect]) as probe,
            ):
                self.assertEqual(approve.serving("my-mac.tail1.ts.net"), expected)
        self.assertEqual(probe.call_args.args[0], ("my-mac.tail1.ts.net", 443))

    def test_serve_runs_only_while_the_page_is_open_and_never_funnel(self):
        proxy = Mock()
        proxy.wait.side_effect = subprocess.TimeoutExpired("serve", 10)
        with (
            patch.object(approve.subprocess, "Popen", return_value=proxy) as popen,
            patch.object(approve, "serving", return_value=False),
            self.assertRaises(KeyError),
        ):
            with approve.tailnet_proxy(self.TAILNET_PAGE(), 8765):
                proxy.terminate.assert_not_called()
                raise KeyError("page failed")
        self.assertEqual(popen.call_args.args[0], [approve.TAILSCALE, "serve", "--bg=false", "http://127.0.0.1:8765"])
        self.assertEqual(popen.call_args.kwargs["env"]["SHLVL"], "1")
        proxy.terminate.assert_called_once()
        proxy.kill.assert_called_once()
        with patch.object(approve.subprocess, "Popen") as popen:
            with approve.tailnet_proxy(approve.RegisterPage([ORIGIN]), 8765) as problem:
                self.assertIsNone(problem)
        popen.assert_not_called()

    def test_never_takes_over_an_existing_serve_setting(self):
        with (
            patch.object(approve.subprocess, "Popen") as popen,
            patch.object(approve, "serving", return_value=True),
            redirect_stdout(io.StringIO()) as printed,
        ):
            with approve.tailnet_proxy(self.TAILNET_PAGE(), 8765) as problem:
                self.assertIsNone(problem)
        popen.assert_not_called()
        self.assertIn("no iPhone link", printed.getvalue())

    def test_a_plain_kill_still_stops_serve(self):
        child = textwrap.dedent(f"""
            import subprocess, sys
            sys.path.insert(0, {str(Path(approve.__file__).parent)!r})
            import approve
            approve.serving = lambda host: False
            real = subprocess.Popen
            def fake(*args, **kwargs):
                proxy = real(["/bin/sleep", "60"])
                print(proxy.pid, flush=True)
                return proxy
            approve.subprocess.Popen = fake
            with approve.tailnet_proxy(approve.RegisterPage(["https://my-mac.tail1.ts.net"]), 8765):
                approve.threading.Event().wait(60)
            """)
        runner = subprocess.Popen([sys.executable, "-B", "-c", child], stdout=subprocess.PIPE, text=True)
        self.addCleanup(runner.kill)
        proxy = int(runner.stdout.readline())
        runner.terminate()
        self.assertEqual(runner.wait(15), 143)
        with self.assertRaises(ProcessLookupError):
            os.kill(proxy, 0)

    def test_safari_failure_is_reported(self):
        with patch.object(approve, "SAFARI", ["/usr/bin/false"]), redirect_stdout(io.StringIO()) as printed:
            approve.open_in_safari("http://localhost:1/x/")
        self.assertIn("open the link above by hand", printed.getvalue())


class Reachable(PageCase):
    def test_true_only_when_the_page_answers(self):
        self.serve()
        link = self.page.link(self.origin)
        self.assertTrue(approve.reachable(link, Mock(poll=Mock(return_value=None))))
        self.assertFalse(approve.reachable(link, Mock(poll=Mock(return_value=1))))
        self.assertFalse(
            approve.reachable(f"http://localhost:{free_port()}/x/", Mock(poll=Mock(return_value=None)), seconds=0.5)
        )


class Ensure(PageCase):
    """The runner asks in Safari only when the grant is not approved yet, and goes on after the tap."""

    def test_tap_in_safari_is_the_go(self):
        self.port = free_port()
        self.key.origin = self.origin = f"http://localhost:{self.port}"
        trust(self, lambda: [self.key.record()])
        opened = []

        def safari(link):
            # What Safari and Touch ID do: load the options, sign, post.
            opened.append(link)
            self.token = link.split("/")[-2]
            self.assertEqual(self.request("POST", "done", self.approval()[1])[0], 200)

        printed = io.StringIO()
        with (
            patch.object(approve, "open_in_safari", safari),
            patch.object(approve, "tailnet_origin", lambda: None),
            redirect_stdout(printed),
        ):
            approve.ensure(self.run, self.port, minutes=1)
            self.assertEqual(grants.verified(self.run), self.grant)
            approve.ensure(self.run, self.port, minutes=1)
        self.assertEqual(len(opened), 1)
        self.assertIn(f"Open on the Mac: {opened[0]}", printed.getvalue())
        self.assertTrue(opened[0].startswith(f"{self.origin}/"))

    def test_no_tap_means_no_go(self):
        port = free_port()
        self.key.origin = f"http://localhost:{port}"
        with (
            patch.object(approve, "open_in_safari", lambda link: None),
            patch.object(approve, "tailnet_origin", lambda: None),
            redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(grants.GrantError, "without approval"),
        ):
            approve.ensure(self.run, port, minutes=0.01)
        self.assertFalse((self.run / grants.APPROVAL).exists())


if __name__ == "__main__":
    unittest.main()

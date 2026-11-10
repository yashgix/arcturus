"""Passkey (WebAuthn ES256) approval of an exact grant: Touch ID on the Mac or Face ID on the iPhone.

Checks the parts of WebAuthn Level 3 section 7.2 that bind an assertion to this site, this exact grant and a
verified user, with the standard library and the Mac's /usr/bin/openssl. Attestation is not used: the trust anchor
is the root-owned record of each passkey, installed with the operator's sudo once.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

import operator_approval

TRUST = operator_approval.SIGNERS.parent / "passkeys"
PURPOSE = b"arcturus-grant-approval-v1\0"
# SubjectPublicKeyInfo header of an uncompressed P-256 key, the form getPublicKey() returns for ES256.
P256_SPKI = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
ES256 = -7
USER_PRESENT, USER_VERIFIED, ATTESTED = 0x01, 0x04, 0x40
MAX_FIELD = 4096
RECORD = {"credential_id", "public_key", "origin", "registered"}
ASSERTION = {"credential_id", "nonce", "client_data", "authenticator_data", "signature"}
CREATION = {"credential_id", "client_data", "authenticator_data", "public_key", "algorithm"}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text):
    if not isinstance(text, str) or not 0 < len(text) <= MAX_FIELD:
        raise ValueError("malformed passkey field")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ValueError("malformed passkey field") from exc


def rp_id(origin):
    """The passkey's site for an origin: https, or http only on localhost for use at the Mac."""
    parts = urlsplit(origin) if isinstance(origin, str) else None
    if (
        not parts
        or not parts.hostname
        or origin != f"{parts.scheme}://{parts.netloc}"
        or "@" in parts.netloc
        or not (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname == "localhost"))
    ):
        raise ValueError(f"unsupported approval origin {origin!r}")
    return parts.hostname


def challenge(digest, nonce):
    return hashlib.sha256(PURPOSE + bytes.fromhex(digest) + nonce).digest()


def fingerprint(record):
    return hashlib.sha256(unb64(record["public_key"])).hexdigest()


def check_record(record):
    if not isinstance(record, dict) or set(record) != RECORD or not isinstance(record["registered"], int):
        raise ValueError("malformed passkey record")
    key = unb64(record["public_key"])
    if len(key) != len(P256_SPKI) + 64 or not key.startswith(P256_SPKI):
        raise ValueError("passkey is not an ES256 P-256 key")
    if len(unb64(record["credential_id"])) > 1023:
        raise ValueError("passkey credential id is too long")
    rp_id(record["origin"])
    return record


def credentials():
    """The trusted passkeys; each file and folder must be root-owned. None installed means none trusted."""
    if not os.path.lexists(TRUST):
        return []
    operator_approval.root_owned(TRUST, is_file=False)
    records = []
    for path in sorted(TRUST.iterdir()):
        operator_approval.root_owned(path)
        records.append(check_record(json.loads(path.read_bytes())))
    return records


def check_client_data(raw, kind, expected, origin):
    data = json.loads(raw)
    if (
        not isinstance(data, dict)
        or data.get("type") != kind
        or data.get("challenge") != b64(expected)
        or data.get("origin") != origin
        or data.get("crossOrigin") not in (None, False)
        or "topOrigin" in data
    ):
        raise ValueError("passkey response is not for this page and request")


def check_authenticator_data(raw, origin, flags):
    if len(raw) < 37 or raw[:32] != hashlib.sha256(rp_id(origin).encode()).digest():
        raise ValueError("passkey response is for another site")
    if raw[32] & flags != flags:
        raise ValueError("passkey response lacks user presence or verification")


def check_es256(public_key, signed, signature):
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(public_key) + b"-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as folder:
        files = {name: Path(folder) / name for name in ("key.pem", "signature", "data")}
        for path, content in zip(files.values(), (pem, signature, signed)):
            path.write_bytes(content)
        try:
            result = subprocess.run(
                [
                    "/usr/bin/openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    files["key.pem"],
                    "-signature",
                    files["signature"],
                    files["data"],
                ],
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("passkey signature verifier is unavailable") from exc
    if result.returncode or result.stdout.strip() != b"Verified OK":
        raise ValueError("passkey signature is not valid")


def verify(digest, approval):
    """Raise unless a trusted passkey approved exactly this grant digest with user verification."""
    if (
        not isinstance(approval, dict)
        or set(approval) != ASSERTION
        or not all(isinstance(value, str) for value in approval.values())
    ):
        raise ValueError("malformed passkey approval")
    record = {r["credential_id"]: r for r in credentials()}.get(approval["credential_id"])
    if not record:
        raise ValueError("approval is not from a trusted passkey")
    nonce, client, authenticator = (unb64(approval[k]) for k in ("nonce", "client_data", "authenticator_data"))
    if not 16 <= len(nonce) <= 64:
        raise ValueError("malformed passkey approval")
    check_client_data(client, "webauthn.get", challenge(digest, nonce), record["origin"])
    check_authenticator_data(authenticator, record["origin"], USER_PRESENT | USER_VERIFIED)
    check_es256(
        unb64(record["public_key"]), authenticator + hashlib.sha256(client).digest(), unb64(approval["signature"])
    )
    return record


def registration(response, nonce, origin):
    """Check a new passkey's creation response; return the record to install. Installing it is what trusts it."""
    if not isinstance(response, dict) or set(response) != CREATION or response["algorithm"] != ES256:
        raise ValueError("malformed passkey registration or not ES256")
    credential = unb64(response["credential_id"])
    record = check_record(
        {
            "credential_id": b64(credential),
            "public_key": response["public_key"],
            "origin": origin,
            "registered": int(time.time()),
        }
    )
    client, authenticator = unb64(response["client_data"]), unb64(response["authenticator_data"])
    check_client_data(client, "webauthn.create", nonce, origin)
    check_authenticator_data(authenticator, origin, USER_PRESENT | USER_VERIFIED | ATTESTED)
    return record


def install_command(record):
    """The one sudo command that trusts this passkey. Root runs only fixed shell commands; no file is read."""
    name = TRUST / f"{fingerprint(record)}.json"
    blob = base64.b64encode(json.dumps(check_record(record), sort_keys=True).encode()).decode()
    return (
        f"/usr/bin/sudo -k /bin/sh -c 'set -eu; umask 022; /bin/mkdir -p {TRUST}; [ ! -e {name} ]; "
        f"echo {blob} | /usr/bin/base64 -D > {name}.tmp; /bin/mv {name}.tmp {name}; echo TRUSTED {name}'"
    )

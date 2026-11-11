"""One operator-signed budget grant per workflow, enforced by a local spending ledger.

A grant fixes the models, ceilings, scope, expiry and the hash of the enforcement code. Calls inside it need no
further signature; anything outside it is refused.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import threading
import time

from api_review import encode
import operator_approval
import passkey

RUNNER = Path(__file__).resolve().parent
ENFORCEMENT = (
    "grant.py",
    "llm.py",
    "gateway.py",
    "broker.py",
    "evaluate.py",
    "sandbox.py",
    "opencode.py",
    "build.py",
    "workflow.py",
    "operator_approval.py",
    "passkey.py",
    "approve.py",
    "approve.js",
    "paid_review.py",
    "api_review.py",
)
SIGNATURES = operator_approval.SIGNERS.parent
PRINCIPAL = "arcturus-operator"
LIMITS = {
    "research": "No builds, sends or publication.",
    "build": "Local builds in sandboxed workspaces only. Experiments a spec declares may call only the "
    "models listed above, through the local broker. No pushes, sends or publication.",
    "evaluate": "Model calls for one sandboxed evaluation through the local broker only. No builds, sends or "
    "publication.",
}
SIGNING_KEY = Path("/private/etc/arcturus-operator-private/signing-key")
APPROVAL = "grant.approval.json"
COMPANY_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")


class GrantError(Exception):
    pass


def enforcement_sha256():
    hashed = hashlib.sha256()
    for name in ENFORCEMENT:
        hashed.update(name.encode() + b"\0" + (RUNNER / name).read_bytes() + b"\0")
    return hashed.hexdigest()


def draft(purpose, scope, models, ceiling_usd, max_calls, hours, prior=None):
    return {
        "version": 1,
        "id": f"{purpose}-{secrets.token_hex(6)}",
        "purpose": purpose,
        "scope": scope,
        "models": models,
        "ceiling_microusd": round(ceiling_usd * 1_000_000),
        "max_calls": max_calls,
        "expires_at": int(time.time() + hours * 3600),
        "data_class": "public",
        "enforcement_sha256": enforcement_sha256(),
        "prior_commitments": prior or {},
    }


def payload(grant):
    return encode({"purpose": operator_approval.NAMESPACE, "grant": grant}) + b"\n"


def digest(grant):
    return hashlib.sha256(payload(grant)).hexdigest()


def companies(scope):
    if "company_ids" in scope:
        return f"{', '.join(scope.get('companies', []))} (ids {', '.join(scope['company_ids'])})"
    return f"any companies the pipeline queue admits, at most {scope['max_companies']}"


def describe(grant):
    scope = grant["scope"]
    return (
        f"GRANT {grant['id']}: {grant['purpose']} for {companies(scope)} "
        f"(operations {', '.join(scope.get('operations', []))}). "
        f"Models {', '.join(grant['models'])}. Ceiling ${grant['ceiling_microusd'] / 1e6:.2f}, at most "
        f"{grant['max_calls']} calls, expires {time.strftime('%Y-%m-%d %H:%M', time.localtime(grant['expires_at']))}. "
        f"Retries and repairs inside these limits need no new signature. {LIMITS[grant['purpose']]}"
    )


def signature_path(grant):
    return SIGNATURES / f"grant-{digest(grant)}.sig"


def write(run, grant):
    """Write the grant and the one root-only signing script the operator runs."""
    run = Path(run)
    (run / APPROVAL).unlink(missing_ok=True)
    (run / "grant.json").write_text(json.dumps(grant, indent=2) + "\n")
    (run / "grant.payload").write_bytes(payload(grant))
    sha, exported = digest(grant), signature_path(grant)
    summary = describe(grant)
    script = f"""#!/bin/sh
set -eu
umask 077
[ "$(/usr/bin/id -u)" = 0 ] || {{ echo 'Administrator authentication required.' >&2; exit 1; }}
key={SIGNING_KEY}
[ ! -L "$key" ] && [ "$(/usr/bin/stat -f %u "$key")" = 0 ] && [ "$(/usr/bin/stat -f %Lp "$key")" = 400 ] || exit 1
[ ! -e {exported} ] || {{ echo 'Grant already signed.' >&2; exit 1; }}
d=$(/usr/bin/mktemp -d /private/var/root/arcturus-grant.XXXXXXXX)
trap '/bin/rm -f "$d/grant.payload" "$d/grant.payload.sig"; /bin/rmdir "$d"' EXIT
/bin/cp {run / 'grant.payload'} "$d/grant.payload"
[ "$(/usr/bin/shasum -a 256 "$d/grant.payload" | /usr/bin/cut -d ' ' -f 1)" = {sha} ] || {{ echo 'Grant changed. Refusing to sign.' >&2; exit 1; }}
/usr/bin/plutil -p "$d/grant.payload"
echo {shlex.quote(summary)}
/usr/bin/ssh-keygen -Y sign -f "$key" -n {operator_approval.NAMESPACE} "$d/grant.payload" < /dev/tty
/usr/bin/ssh-keygen -Y verify -f {operator_approval.SIGNERS} -I {PRINCIPAL} -n {operator_approval.NAMESPACE} -s "$d/grant.payload.sig" < "$d/grant.payload"
/bin/cp "$d/grant.payload.sig" {exported}
/bin/chmod 0644 {exported}
echo "SIGNED {exported}"
"""
    (run / "sign-grant.sh").write_text(script)
    script_sha = hashlib.sha256(script.encode()).hexdigest()
    command = (
        "/usr/bin/sudo -k /usr/bin/env -i PATH=/usr/bin:/bin HOME=/private/var/root /bin/sh -c 'set -eu; "
        "d=$(/usr/bin/mktemp -d /private/var/root/arcturus-sign.XXXXXXXX); "
        "trap \"/bin/rm -f $d/sign.sh; /bin/rmdir $d\" EXIT; "
        f"/bin/cp {run / 'sign-grant.sh'} $d/sign.sh; "
        f"[ \"$(/usr/bin/shasum -a 256 $d/sign.sh | /usr/bin/cut -c 1-64)\" = {script_sha} ] || exit 1; "
        "/bin/sh $d/sign.sh'"
    )
    (run / "sign-command.txt").write_text(command + "\n")
    return command


def approve(run, grant, approval):
    """Store a passkey approval of exactly this grant; it is checked again on every use."""
    passkey.verify(digest(grant), approval)
    fd = os.open(Path(run) / APPROVAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as file:
        json.dump(approval, file)


def check_approved(run, grant):
    """Either proof will do: a passkey approval in the run folder or the operator's sudo signature."""
    problems = []
    approval = Path(run) / APPROVAL
    if os.path.lexists(approval):
        try:
            passkey.verify(digest(grant), json.loads(operator_approval.read_signature(approval)))
            return
        except (OSError, ValueError) as exc:
            problems.append(f"passkey approval: {exc}")
    try:
        operator_approval.verify(payload(grant), PRINCIPAL, operator_approval.read_signature(signature_path(grant)))
    except (OSError, ValueError) as exc:
        raise ValueError("; ".join(problems + [f"signature: {exc}"])) from exc


def verified(run):
    """Return the grant only if its operator approval, expiry and enforcement code all still hold."""
    grant = json.loads((Path(run) / "grant.json").read_text())
    try:
        check_approved(run, grant)
    except (OSError, ValueError) as exc:
        raise GrantError(f"grant is not signed by the operator: {exc}") from exc
    if grant["enforcement_sha256"] != enforcement_sha256():
        raise GrantError("enforcement code changed since the grant was signed")
    if time.time() >= grant["expires_at"]:
        raise GrantError("grant expired")
    return grant


class Ledger:
    """Durable reservations. Uncertain calls keep their full reserve; nothing is replayed silently."""

    def __init__(self, path, grant):
        self.grant = grant
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS control (grant_id TEXT PRIMARY KEY, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY, lane TEXT NOT NULL, step TEXT NOT NULL, model TEXT NOT NULL,
                state TEXT NOT NULL, reserve INTEGER NOT NULL, charge INTEGER, usage TEXT, reason TEXT,
                response_id TEXT, started REAL NOT NULL, finished REAL);""")
        self.db.execute("INSERT OR IGNORE INTO control VALUES (?, 'run')", (grant["id"],))

    def recover(self):
        """A reservation left by a crash may have reached the provider."""
        self.db.execute(
            "UPDATE calls SET state='uncertain', reason='runner stopped mid-call', finished=? WHERE state='reserved'",
            (time.time(),),
        )

    def state(self):
        with self.lock:
            return self.db.execute("SELECT state FROM control WHERE grant_id=?", (self.grant["id"],)).fetchone()[0]

    def control(self, state):
        if state not in ("run", "pause", "stop", "revoked"):
            raise ValueError("unknown control state")
        if self.state() == "revoked":
            raise GrantError("a revoked grant cannot be resumed")
        self.db.execute("UPDATE control SET state=? WHERE grant_id=?", (state, self.grant["id"]))

    def covers(self, company):
        """A fixed list names its companies; a standing allowance takes the first max_companies that spend."""
        scope = self.grant["scope"]
        if "company_ids" in scope:
            return company in scope["company_ids"]
        if not COMPANY_ID.fullmatch(company):
            return False
        lanes = (row[0] for row in self.db.execute("SELECT DISTINCT lane FROM calls"))
        seen = {lane.split("/")[0] for lane in lanes}
        return company in seen or len(seen) < scope["max_companies"]

    def committed(self, lane=None):
        with self.lock:
            return self.db.execute(
                "SELECT COALESCE(SUM(CASE WHEN state IN ('reserved','uncertain') THEN reserve "
                "ELSE COALESCE(charge, 0) END), 0) FROM calls WHERE ? IS NULL OR lane = ?",
                (lane, lane),
            ).fetchone()[0]

    def reserve(self, lane, step, model, amount):
        with self.lock:
            return self._reserve(lane, step, model, amount)

    def _reserve(self, lane, step, model, amount):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            calls = self.db.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
            scope = self.grant["scope"]
            reason = (
                "grant is " + self.state()
                if self.state() != "run"
                else "grant expired"
                if time.time() >= self.grant["expires_at"]
                else f"{model} is not in the grant"
                if model not in self.grant["models"]
                else f"company {lane.split('/')[0]} is outside the grant"
                if not self.covers(lane.split("/")[0])
                else f"operation {step} is outside the grant"
                if step.split("-")[0] not in scope["operations"]
                else "call ceiling reached"
                if calls >= self.grant["max_calls"]
                else "spending ceiling reached"
                if self.committed() + amount > self.grant["ceiling_microusd"]
                else f"{lane} reached its share of the grant"
                if lane in scope.get("lane_ceilings_microusd", {})
                and self.committed(lane) + amount > scope["lane_ceilings_microusd"][lane]
                else None
            )
            if reason:
                raise GrantError(reason)
            call = self.db.execute(
                "INSERT INTO calls (lane, step, model, state, reserve, started) VALUES (?, ?, ?, 'reserved', ?, ?)",
                (lane, step, model, amount, time.time()),
            ).lastrowid
            self.db.execute("COMMIT")
            return call
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def settle(self, call, state, charge=None, usage=None, reason=None, response_id=None):
        if charge is not None and (type(charge) is not int or charge < 0):
            state, charge, reason = "uncertain", None, "invalid charge; reserve retained"
        if state == "uncertain":
            charge = None
        with self.lock:
            self.db.execute(
                "UPDATE calls SET state=?, charge=?, usage=?, reason=?, response_id=?, finished=? "
                "WHERE id=? AND state='reserved'",
                (state, charge, json.dumps(usage) if usage else None, reason, response_id, time.time(), call),
            )

    def rows(self):
        with self.lock:
            rows = self.db.execute("SELECT * FROM calls ORDER BY id")
            names = [column[0] for column in rows.description]
            return [dict(zip(names, row)) for row in rows]

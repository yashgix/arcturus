"""Detached operator signatures for exact one-shot model plans."""

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from api_review import encode

NAMESPACE = "arcturus-model-approval-v1"
SIGNERS = Path("/private/etc" if sys.platform == "darwin" else "/etc") / "arcturus/model-approval-signers"
MAX_SIGNATURE = 8192


def configured():
    # An unsafe or dangling entry must require verification and then fail closed.
    try:
        SIGNERS.lstat()
    except FileNotFoundError:
        return False
    return True


def root_owned(target, is_file=True):
    """Raise unless the target and every parent folder are root-owned and writable by no one else."""
    try:
        for path in (*reversed(target.parents), target):
            info = path.lstat()
            kind = stat.S_ISREG if path == target and is_file else stat.S_ISDIR
            if (
                info.st_uid != 0
                or info.st_mode & 0o022
                or not kind(info.st_mode)
                or (os.getuid() != 0 and os.access(path, os.W_OK))
            ):
                raise ValueError(f"trust store {target} is unsafe")
    except OSError as exc:
        raise ValueError(f"trust store {target} is unavailable") from exc
    return target


def trusted_signers():
    return root_owned(SIGNERS)


def message(root, nonce, plan):
    return encode({"purpose": NAMESPACE, "schedule": str(root), "nonce": nonce, "plan": plan}) + b"\n"


def read_signature(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError("operator signature must be a regular file")
        return file.read(MAX_SIGNATURE + 1)


def verify(payload, principal, signature):
    if (
        not isinstance(principal, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}", principal)
        or not isinstance(signature, bytes)
        or not 0 < len(signature) <= MAX_SIGNATURE
    ):
        raise ValueError("invalid operator signature or principal")
    signers = trusted_signers()
    try:
        with tempfile.TemporaryFile(dir="/tmp") as file:
            file.write(signature)
            file.seek(0)
            fd = file.fileno()
            result = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(signers),
                    "-I",
                    principal,
                    "-n",
                    NAMESPACE,
                    "-s",
                    f"/dev/fd/{fd}",
                ],
                input=payload,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                pass_fds=(fd,),
                timeout=5,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("operator signature verifier is unavailable") from exc
    if result.returncode:
        raise ValueError("operator signature is not valid for this exact plan")


def signature_hash(signature):
    return hashlib.sha256(signature).hexdigest()

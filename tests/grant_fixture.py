"""A throwaway operator signer for grant tests: real SSH signatures, test-only trust root."""

from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
import grant as grants
import operator_approval


def signed_root(test, parent="/tmp"):
    """A fresh private folder whose signer the grant code trusts for the length of the test."""
    temporary = tempfile.TemporaryDirectory(dir=parent)
    test.addCleanup(temporary.cleanup)
    root = Path(temporary.name).resolve()
    signer = root / "signer"
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(signer)], check=True)
    signers = root / "allowed-signers"
    signers.write_text(
        f'{grants.PRINCIPAL} namespaces="{operator_approval.NAMESPACE}" ' + signer.with_suffix(".pub").read_text()
    )
    for target, name, replacement in (
        (operator_approval, "trusted_signers", lambda: signers),
        (grants, "SIGNATURES", root),
    ):
        patcher = patch.object(target, name, replacement)
        patcher.start()
        test.addCleanup(patcher.stop)
    test.signer = signer
    return root


def sign(test, draft):
    signature = subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(test.signer), "-n", operator_approval.NAMESPACE],
        input=grants.payload(draft),
        capture_output=True,
        check=True,
    ).stdout
    grants.signature_path(draft).write_bytes(signature)


def keys(root, providers):
    folder = root / "keys"
    folder.mkdir(mode=0o700)
    for provider in providers:
        (folder / provider).write_text(f"fixture-{provider}-key")
        (folder / provider).chmod(0o600)
    return {p: str(folder / p) for p in providers}

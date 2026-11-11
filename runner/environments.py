"""Vetted Python environments for builds. Each recipe in envs/ (packages, lock with hashes, description) is made
into a read-only environment in the execution area by the runner, from PyPI wheels only: nothing is built from
source, so no package install script runs; the only code run at install is a recipe's named setup step (e.g.
Playwright's browser download). An environment made by hand from a project's own lock has only its .json
here. Builders never install anything. A new recipe or package needs Yash's OK.

    python3 runner/environments.py lock NAME   # resolve NAME.in to NAME.lock
    python3 runner/environments.py make NAME   # install NAME.lock into the execution area
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

PYTHON = "/opt/homebrew/bin/python3"
ROOT = Path("/Users/Shared/arcturus-exec/envs")
RECIPES = Path(__file__).with_name("envs")
UV = "/opt/homebrew/bin/uv"
STDLIB = {"python": PYTHON, "read": [], "env": {}, "about": "Python 3.14 standard library only"}


def recipe(name):
    return json.loads((RECIPES / f"{name}.json").read_text())


def available():
    """stdlib, and every recipe whose environment exists on this machine: its Python, the read-only paths it needs
    (the environment, plus e.g. browsers) and its environment variables."""
    envs = {"stdlib": STDLIB}
    for path in sorted(RECIPES.glob("*.json")):
        folder, spec = ROOT / path.stem, recipe(path.stem)
        if (folder / "bin" / "python").exists():
            envs[path.stem] = {
                "python": str(folder / "bin" / "python"),
                "read": [str(folder), *spec.get("read", [])],
                "env": spec.get("env", {}),
                "about": spec["about"],
            }
    return envs


def lock(name):
    subprocess.run(
        [
            UV,
            "pip",
            "compile",
            "--python",
            PYTHON,
            "--only-binary",
            ":all:",
            "--generate-hashes",
            "--no-header",
            "--no-annotate",
            str(RECIPES / f"{name}.in"),
            "-o",
            str(RECIPES / f"{name}.lock"),
        ],
        check=True,
    )


def make(name):
    """Install the lock, hash-checked and wheels only, run the recipe's setup (e.g. Playwright's browser download),
    then make everything read-only; a failed install leaves nothing."""
    target, spec = ROOT / name, recipe(name)
    if target.exists():
        raise SystemExit(f"{target} exists; remove it first to rebuild")
    try:
        subprocess.run([UV, "venv", "--python", PYTHON, str(target)], check=True)
        subprocess.run(
            [
                UV,
                "pip",
                "install",
                "--python",
                str(target / "bin" / "python"),
                "--require-hashes",
                "--only-binary",
                ":all:",
                "--no-deps",
                "-r",
                str(RECIPES / f"{name}.lock"),
            ],
            check=True,
        )
        for args in spec.get("setup", []):
            subprocess.run(
                [str(target / "bin" / "python"), *args], env={**os.environ, **spec.get("env", {})}, check=True
            )
    except subprocess.CalledProcessError:
        shutil.rmtree(target, ignore_errors=True)
        raise
    shutil.copy(RECIPES / f"{name}.lock", target / "requirements.lock")
    subprocess.run(["/bin/chmod", "-R", "a-w", str(target), *spec.get("read", [])], check=True)


if __name__ == "__main__":
    command, env = sys.argv[1:3]
    {"lock": lock, "make": make}[command](env)

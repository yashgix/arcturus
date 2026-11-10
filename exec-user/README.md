# Execution account

Builds and tests run as `_arcexec`, a hidden macOS account with no password, no login shell and no secure token.
It is not in `staff`, so it cannot enter the owner's home folder (mode `750`, group `staff`). Nothing in the home folder is
changed. Jobs live in `/Users/Shared/arcturus-exec/` (owner `yashgx`, mode `700`, one ACL entry letting `_arcexec`
pass through); the runner gives each job's scratch folder its own ACL entries.

- `setup.sh`: creates the account and group (id 490), installs `run-as-exec` root-owned in
  `/usr/local/libexec/arcturus-exec/`, and adds `/etc/sudoers.d/arcturus-exec`: `yashgx` may start that launcher only
  as `_arcexec` inside `_arcexec`'s own launchd session (`launchctl asuser 490`), so jobs can't reach services of
  yashgx's desktop session such as the clipboard; and may run its `stop`. Run once: `sudo sh exec-user/setup.sh`.
- `run-as-exec`: refuses anything but a job folder inside the job area and a command under `sandbox-exec`, with an
  empty environment plus the given variables. `stop` kills every `_arcexec` process.
- `isolation_check.py`: proves the boundary with controls. Run as yashgx: `python3 exec-user/isolation_check.py`.
  Evidence goes to `~/arcturus-runs/exec-isolation/`.
- `undo.sh`: removes all of it. `sudo sh exec-user/undo.sh`.

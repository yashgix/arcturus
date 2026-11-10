#!/bin/sh
# Creates the hidden _arcexec account and the one sudo rule the build runner needs. Run once: sudo sh setup.sh
# Changes nothing else: no home folder permissions, no existing user, group, file or security setting.
# Undo: sudo sh undo.sh
set -eu
NAME=_arcexec
ID=490
OWNER=yashgx
HERE=$(cd "$(dirname "$0")" && pwd)
LIBEXEC=/usr/local/libexec/arcturus-exec
RULE=/etc/sudoers.d/arcturus-exec

[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
grep -Eq '^[#@]includedir /(private/)?etc/sudoers\.d' /etc/sudoers || { echo "/etc/sudoers does not read sudoers.d. Nothing changed."; exit 1; }
if dscl . -read "/Users/$NAME" >/dev/null 2>&1 || dscl . -read "/Groups/$NAME" >/dev/null 2>&1 ||
   dscl . -search /Users UniqueID "$ID" | grep -q . || dscl . -search /Groups PrimaryGroupID "$ID" | grep -q . ||
   [ -e "$RULE" ] || [ -e "$LIBEXEC" ]; then
  echo "$NAME, id $ID, $RULE or $LIBEXEC already exists. Nothing changed."; exit 1
fi

echo "1/3 Group and account $NAME (id $ID): no password, no login shell, hidden, never gets a secure token."
dscl . -create "/Groups/$NAME"
dscl . -create "/Groups/$NAME" PrimaryGroupID "$ID"
dscl . -create "/Groups/$NAME" Password '*'
dscl . -create "/Users/$NAME"
dscl . -create "/Users/$NAME" UniqueID "$ID"
dscl . -create "/Users/$NAME" PrimaryGroupID "$ID"
dscl . -create "/Users/$NAME" UserShell /usr/bin/false
dscl . -create "/Users/$NAME" NFSHomeDirectory /var/empty
dscl . -create "/Users/$NAME" RealName "Arcturus execution"
dscl . -create "/Users/$NAME" Password '*'
dscl . -create "/Users/$NAME" AuthenticationAuthority ';DisabledTags;SecureToken'
dscl . -create "/Users/$NAME" IsHidden 1

echo "2/3 Launcher $LIBEXEC/run-as-exec (root-owned, read-only)."
install -d -o root -g wheel -m 755 "$LIBEXEC"
install -o root -g wheel -m 755 "$HERE/run-as-exec" "$LIBEXEC/run-as-exec"

echo "3/3 Sudo rules: $OWNER may start the launcher only as $NAME, in $NAME's own session (outside yours), and stop it."
tmp=$(mktemp)
{
  printf '%s ALL=(root) NOPASSWD: /bin/launchctl asuser %s /usr/bin/sudo -u %s %s run *\n' "$OWNER" "$ID" "$NAME" "$LIBEXEC/run-as-exec"
  printf '%s ALL=(%s) NOPASSWD: %s stop\n' "$OWNER" "$NAME" "$LIBEXEC/run-as-exec"
} > "$tmp"
visudo -cqf "$tmp"
install -o root -g wheel -m 440 "$tmp" "$RULE"
rm -f "$tmp"
visudo -cq || { rm -f "$RULE"; echo "sudo configuration check failed; rule removed."; exit 1; }

echo "Done. $NAME groups: $(id -Gn "$NAME")"

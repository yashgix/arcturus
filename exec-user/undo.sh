#!/bin/sh
# Reverses setup.sh: stops _arcexec's processes, removes the sudo rule, launcher, account, group and job area.
# Run: sudo sh undo.sh
set -eu
NAME=_arcexec
ID=490
LIBEXEC=/usr/local/libexec/arcturus-exec
RULE=/etc/sudoers.d/arcturus-exec
AREA=/Users/Shared/arcturus-exec

[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
# Only an install that setup.sh made, used by nothing else. Any mismatch or failed lookup: change nothing.
fail() { echo "Not a clean $NAME install from setup.sh ($1). Nothing changed."; exit 1; }
names() { printf '%s\n' "$1" | awk '/^[^ \t)]/ {print $1}'; }
users=$(dscl . -search /Users UniqueID "$ID") || fail "user lookup failed"
groups=$(dscl . -search /Groups PrimaryGroupID "$ID") || fail "group lookup failed"
members=$(dscl . -search /Users PrimaryGroupID "$ID") || fail "group users lookup failed"
group=$(dscl . -read "/Groups/$NAME") || fail "group record lookup failed"
realname=$(dscl . -read "/Users/$NAME" RealName) || fail "real name lookup failed"
[ "$(names "$users")" = "$NAME" ] || fail "id $ID is not only $NAME"
[ "$(names "$groups")" = "$NAME" ] || fail "group id $ID is not only $NAME"
[ "$(names "$members")" = "$NAME" ] || fail "another account uses group $ID"
case "$group" in *GroupMembership:* | *GroupMembers:* | *NestedGroups:*) fail "group $NAME has members" ;; esac
[ "$realname" = "RealName:
 Arcturus execution" ] || fail "real name differs"
[ -f "$LIBEXEC/run-as-exec" ] || fail "launcher missing"
pkill -KILL -u "$ID" 2>/dev/null || true
rm -f "$RULE"
visudo -cq
rm -rf "$LIBEXEC"
rmdir /usr/local/libexec 2>/dev/null || true
dscl . -delete "/Users/$NAME" || { echo "Could not delete user $NAME; group $NAME kept."; exit 1; }
left=$(dscl . -search /Users PrimaryGroupID "$ID") || { echo "Lookup failed; group $NAME kept."; exit 1; }
[ -z "$(names "$left")" ] || { echo "Group $NAME is still a primary group; kept."; exit 1; }
dscl . -delete "/Groups/$NAME"
rm -rf "$AREA"
echo "Removed. Files still owned by id $ID (expected none):"
find /Users/Shared /private/tmp /private/var/tmp /private/var/folders -user "$ID" -prune -print 2>/dev/null || true

#!/bin/sh
# CI: functional s6 test - scan the service dir, assert up/down.
set -eu
: "${SCANDIR:=/tmp/s6-scan}"
test -x "$SCANDIR/crabwalld/run"
s6-svscan "$SCANDIR" &
SCAN="$!"
sleep 3
s6-svstat "$SCANDIR/crabwalld" | grep -q "^up "
s6-svc -d "$SCANDIR/crabwalld"
sleep 1
s6-svstat "$SCANDIR/crabwalld" | grep -q "^down "
kill "$SCAN"
echo "s6 packaging OK"

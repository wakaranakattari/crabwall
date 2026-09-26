#!/bin/sh
# CI: functional runit test - supervise the stub daemon, assert run/stop.
set -eu

test -x /etc/sv/crabwalld/run
test -L /var/service/crabwalld

# sv resolves names against SVDIR (compiled default is /service, NOT
# /var/service), so point it at the dir the installer actually linked
# into instead of hoping the default matches the distro.
SVC=""
for d in /run/runit/service /var/service /service; do
	if [ -e "$d/crabwalld" ]; then
		SVC="$d"
		break
	fi
done
if [ -z "$SVC" ]; then
	echo "no crabwalld entry in any service dir" >&2
	exit 1
fi
export SVDIR="$SVC"

runsvdir "$SVC" &
SV="$!"
# Slow CI runners need a moment before supervise/ appears; poll it.
ok=0
for _ in $(seq 1 15); do
	if sv status crabwalld 2>/dev/null | grep -q "^run:"; then
		ok=1
		break
	fi
	sleep 1
done
if [ "$ok" -ne 1 ]; then
	echo "service never reached run state:" >&2
	sv status crabwalld || true
	kill "$SV" || true
	exit 1
fi
sv stop crabwalld
sleep 1
sv status crabwalld | grep -q "^down:"
kill "$SV"
echo "runit packaging OK"

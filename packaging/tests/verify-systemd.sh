#!/bin/sh
# CI: assert systemd service installed + enabled (no booted systemd needed).
set -eu
test -f /etc/systemd/system/crabwalld.service
test -L /etc/systemd/system/multi-user.target.wants/crabwalld.service
if command -v systemd-analyze >/dev/null 2>&1; then
	systemd-analyze verify /etc/systemd/system/crabwalld.service
fi
echo "systemd packaging OK"

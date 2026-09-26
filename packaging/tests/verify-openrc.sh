#!/bin/sh
# CI: assert OpenRC service installed + registered in the default runlevel.
set -eu
test -x /etc/init.d/crabwalld
rc-update show default | grep -q crabwalld
echo "openrc packaging OK"

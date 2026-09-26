#!/bin/sh
# CI: functional SysVinit test - start/status/stop the stub daemon.
set -eu
test -x /etc/init.d/crabwalld
/etc/init.d/crabwalld start
sleep 1
/etc/init.d/crabwalld status | grep -q "is running"
/etc/init.d/crabwalld stop
sleep 1
/etc/init.d/crabwalld status | grep -q "is not running"
echo "sysvinit packaging OK"

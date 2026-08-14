#!/bin/bash
#
# Guest side of the VM integration test: stage the tree where fw_reload expects
# it, then run the same checks the container harness runs.

set -eu

mkdir -p /cfirewalld /usr/lib/cfirewalld /run/cfirewalld /var/lib/cfirewalld /etc/cfirewalld

cp -a /src/fw_reload /src/subcommands /cfirewalld/
cp -a /src/tests/firewall.d /cfirewalld/
cp /src/cfw-build /usr/lib/cfirewalld/cfw-build
chmod +x /usr/lib/cfirewalld/cfw-build /cfirewalld/fw_reload /cfirewalld/subcommands/*

# conntrackd is not installed here, and the reload would wait on it.
echo "export CONNTRACK_ENABLED=0" > /etc/cfirewalld/fw_vars

cp /src/tests/run.sh /cfirewalld/run.sh
chmod +x /cfirewalld/run.sh

export CFW_TEST_WORK=/out
exec /cfirewalld/run.sh

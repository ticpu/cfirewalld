#!/bin/bash
#
# A container cannot load a kernel module, and the kernel autoloads a set type
# only on first use by a process allowed to. On a machine where nothing has
# used ipset yet, the fixture's sets cannot be created and the failure surfaces
# far from its cause.

set -eu

MODULES="ip_set ip_set_hash_net ip_set_hash_netport ip_set_bitmap_port xt_set"

if [ "$(id -u)" -eq 0 ]; then
	modprobe $MODULES
else
	sudo modprobe $MODULES
fi

echo "loaded: $MODULES"

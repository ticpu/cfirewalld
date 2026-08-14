#!/bin/bash
#
# Drive the integration tests in a container.
#
# The container has its own network namespace, so the firewall it builds is
# unreachable from the host. NET_ADMIN drives iptables and ipset; SYS_MODULE is
# what an `-m set` match needs, because the kernel checks for it before finding
# xt_set already resident. Rootless podman cannot load a module whatever the
# capability says, so the modules have to be on the host already.

set -e

# Named rather than probed: a missing module surfaces during the run as
# "Can't open socket to ipset", which says nothing about what to do.
MODULES="ip_set xt_set ip_set_hash_net ip_set_hash_netport ip_set_bitmap_port"
missing=""
for m in $MODULES; do
	grep -qE "^${m//-/_} " /proc/modules || missing="$missing $m"
done
if [ -n "$missing" ]; then
	echo "Kernel modules not loaded:$missing" 1>&2
	echo "A rootless container cannot load them. Run: sudo modprobe$missing" 1>&2
	exit 1
fi

if command -v podman >/dev/null; then
	CONTAINER_CMD=podman
elif command -v docker >/dev/null; then
	CONTAINER_CMD=docker
else
	echo "Neither podman nor docker found." 1>&2
	exit 1
fi

cd "$(dirname "$0")/.."

if [ ! -x cfw-build ]; then
	echo "cfw-build is missing; run ./build-helper.sh first." 1>&2
	exit 1
fi

IMG=cfirewalld-test:latest
$CONTAINER_CMD build -q -f tests/Containerfile -t "$IMG" tests/ >/dev/null

# The source tree is mounted rather than copied so a test run needs no rebuild
# of the image, and :ro keeps a test from editing the checkout. Only the
# fixture config and the helper are placed where fw_reload expects them.
# A failing run has to leave its logs and captures behind; the container is
# removed on exit, so they are written to a mounted directory.
OUT="${CFW_TEST_OUT:-$PWD/tests/out}"
rm -rf "$OUT"
mkdir -p "$OUT"
echo "artifacts: $OUT"

exec $CONTAINER_CMD run --rm \
	--cap-add=NET_ADMIN --cap-add=NET_RAW \
	-v "$PWD:/src:ro" \
	-v "$OUT:/out:z" \
	"$IMG" \
	bash -c '
		set -e
		mkdir -p /cfirewalld /usr/lib/cfirewalld /run/cfirewalld /var/lib/cfirewalld /etc/cfirewalld
		cp -a /src/fw_reload /src/subcommands /cfirewalld/
		cp -a /src/tests/firewall.d /cfirewalld/
		cp /src/cfw-build /usr/lib/cfirewalld/cfw-build
		# fw_vars sources this; conntrackd is not present in the image.
		echo "export CONNTRACK_ENABLED=0" > /etc/cfirewalld/fw_vars
		cp /src/tests/run.sh /cfirewalld/run.sh
		chmod +x /cfirewalld/run.sh
		exec /cfirewalld/run.sh
	'

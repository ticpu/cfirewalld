#!/bin/bash
#
# Drive the integration tests in a container.
#
# The container has its own network namespace, so the firewall it builds is
# unreachable from the host. NET_ADMIN drives iptables and ipset; NET_RAW is
# what an `-m set` match needs, and without it ipset keeps working while every
# rule referencing a set fails to install. ./tests/check-netfilter.sh answers
# whether a given machine grants both, and ./tests/load-modules.sh loads the set
# types a container cannot load for itself.

set -e

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

# The base image is selectable so CI can run the same tests across the
# distributions the package targets.
BASE="${CFW_TEST_IMAGE:-docker.io/library/debian:bookworm-slim}"
IMG="cfirewalld-test:$(echo "$BASE" | tr '/:' '--')"
$CONTAINER_CMD build -q --build-arg "BASE=$BASE" -f tests/Containerfile -t "$IMG" tests/ >/dev/null

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

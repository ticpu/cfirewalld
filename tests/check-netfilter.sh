#!/bin/bash
#
# Report whether this machine can run the integration tests at all.
#
# NET_ADMIN drives iptables and ipset; without NET_RAW an `-m set` match cannot
# reach the ipset subsystem, and every rule using an alias then fails to install
# while ipset itself keeps working — a failure that reads as a cfirewalld bug.

set -eu

IMAGE="${1:-docker.io/library/debian:bookworm-slim}"

if command -v podman >/dev/null; then
	CONTAINER_CMD=podman
elif command -v docker >/dev/null; then
	CONTAINER_CMD=docker
else
	echo "Neither podman nor docker found." 1>&2
	exit 1
fi

exec $CONTAINER_CMD run --rm \
	--cap-add=NET_ADMIN --cap-add=NET_RAW \
	"$IMAGE" sh -c '
		apt-get update -qq >/dev/null 2>&1
		apt-get install -y -qq iptables ipset >/dev/null 2>&1
		ipset create probe hash:net family inet
		iptables -t filter -N PROBE
		iptables -t filter -A PROBE -m set --match-set probe src -j ACCEPT
		echo "set matches work here"
	'

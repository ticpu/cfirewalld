#!/bin/bash
#
# Build the cfw-build helper in a container so the build host needs no Rust
# toolchain. Built against bullseye, so the result runs on Debian 11 and newer.

set -e

if command -v podman >/dev/null; then
	CONTAINER_CMD=podman
elif command -v docker >/dev/null; then
	CONTAINER_CMD=docker
else
	echo "Neither podman nor docker found." 1>&2
	exit 1
fi

case "${1:-x86_64}" in
	x86_64|amd64)   TARGET=x86_64-unknown-linux-gnu;  SUFFIX=amd64 ;;
	aarch64|arm64)  TARGET=aarch64-unknown-linux-gnu; SUFFIX=arm64 ;;
	*)
		echo "Usage: $0 [x86_64|aarch64]" 1>&2
		exit 2
		;;
esac

IMG="cfirewalld-build:${TARGET}"

$CONTAINER_CMD build -f Containerfile --build-arg "TARGET=$TARGET" -t "$IMG" .
CONTAINER=$($CONTAINER_CMD create "$IMG")
# Suffixed for cross-builds; the package installs the unsuffixed name.
$CONTAINER_CMD cp "$CONTAINER:/app/cfw-build" "cfw-build.$SUFFIX"
$CONTAINER_CMD rm "$CONTAINER"
$CONTAINER_CMD image rm "$IMG"

cp "cfw-build.$SUFFIX" cfw-build

echo "Built cfw-build.$SUFFIX"

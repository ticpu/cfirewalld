#!/bin/bash
#
# Run the integration tests in a Debian VM.
#
# A container cannot do this: xt_set fails to reach the ipset subsystem from a
# container's network namespace, whatever capabilities it is given, so every
# rule matching an alias fails to install. A VM has a real one.
#
# The image is Debian's official cloud image, pinned by URL and checksum, so a
# run tests the netfilter and iptables the package is deployed against rather
# than whatever the host happens to have.

set -eu

# Debian 12, pinned to a dated build rather than latest/, which is rebuilt in
# place. Update the URL and the checksum together; taking the checksum from the
# build's own SHA512SUMS is what makes a run reproducible.
# The `generic` variant, not `genericcloud`: the latter is minimized and ships
# no virtio-9p driver, so the shared directory carrying the source tree and the
# results cannot be mounted.
IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/20260806-2562/debian-12-generic-amd64-20260806-2562.qcow2"
IMAGE_SHA="0b04eda1c80b255d6234ae6fe63c43a6cb0de4afc5c37873acbc82d5b1feba7a619d2402d2341af1cf9e0898fa7d5225be343fef47349b18fe28b838001bd8eb"

cd "$(dirname "$0")/.."
CACHE="${CFW_VM_CACHE:-$PWD/tests/cache}"
OUT="${CFW_TEST_OUT:-$PWD/tests/out}"
BASE="$CACHE/$(basename "$IMAGE_URL")"

if [ ! -x cfw-build ]; then
	echo "cfw-build is missing; run ./build-helper.sh first." 1>&2
	exit 1
fi

mkdir -p "$CACHE"
rm -rf "$OUT"
mkdir -p "$OUT"

# Fetch once. The checksum is verified on every run, not only on download, so a
# truncated or tampered cache cannot silently persist.
if [ ! -f "$BASE" ]; then
	echo "fetching $(basename "$IMAGE_URL")"
	curl -fL --progress-bar -o "$BASE.part" "$IMAGE_URL"
	mv "$BASE.part" "$BASE"
fi

if ! echo "$IMAGE_SHA  $BASE" | sha512sum -c --quiet -; then
	echo "checksum mismatch for $BASE" 1>&2
	echo "expected $IMAGE_SHA" 1>&2
	echo "actual   $(sha512sum "$BASE" | cut -d' ' -f1)" 1>&2
	exit 1
fi

WORK=$(mktemp -d "$PWD/tests/.vm.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# Copy-on-write overlay: the pristine image is never written to.
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$WORK/disk.qcow2" 8G

# cloud-init runs the test and powers off. Output goes to the 9p share, which
# is what survives for inspection when something fails.
cat > "$WORK/user-data" <<'CLOUDINIT'
#cloud-config
package_update: true
packages:
  - ipset
runcmd:
  - [ modprobe, 9pnet_virtio ]
  - [ mkdir, -p, /src, /out ]
  - [ mount, -t, 9p, -o, "trans=virtio,version=9p2000.L,ro", src, /src ]
  - [ mount, -t, 9p, -o, "trans=virtio,version=9p2000.L", out, /out ]
  - [ sh, -c, "bash /src/tests/vm-guest.sh > /out/console.log 2>&1; echo $? > /out/status; sync" ]
  - [ poweroff, -f ]
CLOUDINIT

printf 'instance-id: cfw-test\nlocal-hostname: cfw-test\n' > "$WORK/meta-data"

xorriso -as mkisofs -quiet -output "$WORK/seed.iso" \
	-volid cidata -joliet -rock "$WORK/user-data" "$WORK/meta-data"

ACCEL=tcg
[ -w /dev/kvm ] && ACCEL=kvm

echo "booting Debian VM (accel=$ACCEL); artifacts: $OUT"

# User-mode networking, needed only to apt-get ipset: the image ships iptables
# but not ipset. The guest's firewall is its own, so nothing it builds can
# reach the host.
timeout 600 qemu-system-x86_64 \
	-machine accel=$ACCEL -cpu host -smp 2 -m 1024 \
	-nographic -serial file:"$OUT/boot.log" -monitor none \
	-drive file="$WORK/disk.qcow2",format=qcow2,if=virtio \
	-drive file="$WORK/seed.iso",format=raw,if=virtio,readonly=on \
	-fsdev local,id=src,path="$PWD",security_model=none,readonly=on \
	-device virtio-9p-pci,fsdev=src,mount_tag=src \
	-fsdev local,id=out,path="$OUT",security_model=none \
	-device virtio-9p-pci,fsdev=out,mount_tag=out \
	-nic user,model=virtio-net-pci \
	|| true

if [ ! -f "$OUT/status" ]; then
	echo "the VM produced no result; see $OUT/boot.log" 1>&2
	exit 1
fi

cat "$OUT/console.log"
exit "$(cat "$OUT/status")"

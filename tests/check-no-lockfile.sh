#!/bin/bash
# Cargo.lock belongs only on a release tag's own detached commit, never on a
# branch. The pre-push hook enforces this where it was installed; CI enforces it
# everywhere.

set -e

cd "$(dirname "$0")/.."

if git ls-tree --name-only HEAD -- Cargo.lock | grep -q .; then
	echo "Cargo.lock is tracked at HEAD; it belongs only on a release tag's commit." 1>&2
	exit 1
fi

exit 0

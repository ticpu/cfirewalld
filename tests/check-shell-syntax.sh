#!/bin/bash
#
# Every shell script in the tree must parse. A syntax error here is only found
# at reload time otherwise, which is when the firewall is being rebuilt.

set -eu

cd "$(dirname "$0")/.."

failed=0
for f in fw_reload fw_vars subcommands/* scripts/* hooks/* tests/*.sh; do
	[ -f "$f" ] || continue
	head -1 "$f" | grep -q '^#!.*sh' || continue
	if ! bash -n "$f"; then
		echo "syntax error in $f" 1>&2
		failed=$((failed + 1))
	fi
done

[ "$failed" -eq 0 ] || exit 1
echo "all shell scripts parse"

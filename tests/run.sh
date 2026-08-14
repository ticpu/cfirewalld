#!/bin/bash
#
# Integration tests. Runs inside a container whose network namespace is its
# own, so the rules built here cannot reach the host firewall.
#
# Both build paths run against one config and their results are diffed: the
# helper is only correct if it agrees with the BASH implementation it replaces.

set -u

FAILED=0
# Mounted from the host so a failing run leaves its logs and captures behind.
WORK=${CFW_TEST_WORK:-/out}
mkdir -p "$WORK"

fail () {
	echo "FAIL: $*" 1>&2
	FAILED=$((FAILED + 1))
}

pass () {
	echo "ok: $*"
}

# Strip what legitimately differs between two runs: the ipset version prefix,
# packet counters, and the random hash seed ipset assigns at creation.
normalise () {
	sed -e 's/CFW_[0-9]\+_/CFW_N_/g' \
	    -e 's/ packets [0-9]\+ bytes [0-9]\+//' \
	    -e 's/ initval 0x[0-9a-f]*//' \
	    -e '/^#/d'
}

# Answer the apply prompt with y, and the post-run prompt if one exists.
# fw_reload's own trace goes to its log socket, which a background tail relays
# to the stderr it inherited, so redirecting here captures only what escapes it.
reload () {
	printf 'y\ny\n' | timeout 120 ./fw_reload > "$1" 2>&1
	echo $?
}

# A commit is what advances the set version; a run that applies and rolls back
# leaves it alone.
ipset_version () {
	cat /run/cfirewalld/ipset_prefix 2>/dev/null || echo 0
}

capture () {
	iptables-save  | normalise > "$1/v4.rules"
	ip6tables-save | normalise > "$1/v6.rules"
	# Sorted: `ipset save` fixes no order between sets, and the two build paths
	# create them in different sequences. Order within a rule chain is policy
	# and is compared as-is above; order between sets is not.
	ipset save     | normalise | sort > "$1/sets.list"
}

reset_state () {
	# Between paths: drop everything cfirewalld owns so each run starts level.
	for b in iptables ip6tables; do
		for t in filter nat mangle; do
			$b -t $t -S 2>/dev/null | sed -n 's/^-A \(INPUT\|FORWARD\|OUTPUT\|PREROUTING\|POSTROUTING\) -j \(CFW[A-Z]*_.*\)/-t '"$t"' -D \1 -j \2/p' \
				| while read -r args; do $b $args 2>/dev/null; done
			for c in $($b -t $t -S 2>/dev/null | sed -n 's/^-N \(CFW[A-Z]*_.*\)/\1/p'); do
				$b -t $t -F "$c" 2>/dev/null
			done
			for c in $($b -t $t -S 2>/dev/null | sed -n 's/^-N \(CFW[A-Z]*_.*\)/\1/p'); do
				$b -t $t -X "$c" 2>/dev/null
			done
		done
	done
	ipset list -n 2>/dev/null | grep '^CFW' | while read -r s; do ipset destroy "$s" 2>/dev/null; done
	rm -f /run/cfirewalld/ipset_prefix /tmp/cfw_commit_in_progress
}

cd /cfirewalld

echo "=== BASH build path ==="
reset_state
mkdir -p "$WORK/bash"
before=$(ipset_version)
rc=$(CFW_HELPER=0 reload "$WORK/bash/reload.log")
capture "$WORK/bash"
[ "$rc" = 0 ] && [ "$(ipset_version)" != "$before" ] \
	&& pass "bash path committed" \
	|| fail "bash path did not commit (rc=$rc, version $before -> $(ipset_version))"

echo "=== helper build path ==="
reset_state
mkdir -p "$WORK/helper"
before=$(ipset_version)
rc=$(reload "$WORK/helper/reload.log")
capture "$WORK/helper"
[ "$rc" = 0 ] && [ "$(ipset_version)" != "$before" ] \
	&& pass "helper path committed" \
	|| fail "helper path did not commit (rc=$rc, version $before -> $(ipset_version))"

echo "=== the two paths agree ==="
for f in v4.rules v6.rules sets.list; do
	if diff -u "$WORK/bash/$f" "$WORK/helper/$f" > "$WORK/$f.diff"; then
		pass "$f identical"
	else
		fail "$f differs:"
		head -40 "$WORK/$f.diff" 1>&2
	fi
done

echo "=== shapes reached the ruleset ==="
V4="$WORK/helper/v4.rules"
V6="$WORK/helper/v6.rules"

check () {
	local file="$1" pattern="$2" what="$3"
	grep -q -- "$pattern" "$file" && pass "$what" || fail "$what (no match for: $pattern)"
}

absent () {
	local file="$1" pattern="$2" what="$3"
	grep -q -- "$pattern" "$file" && fail "$what (unexpectedly present: $pattern)" || pass "$what"
}

check  "$V4" 'match-set CFW_N_ported_svc dst,dst' "two-dimensional set emits two directions"
check  "$V4" 'match-set CFW_N_bare_ports dst'     "port bitmap is one-dimensional"
check  "$V4" 'match-set CFW_N_v4_only src'        "v4-only alias present in v4"
absent "$V6" 'CFW_N_v4_only'                      "v4-only alias absent from v6"
check  "$V6" 'match-set CFW_N_v6_only_v6 src'     "v6-only alias present in v6"
absent "$V4" 'CFW_N_v6_only'                      "v6-only alias absent from v4"
check  "$V4" 'icmp-type 8'                        "v4-only option kept in v4"
absent "$V6" 'icmp-type'                          "v4-only option absent from v6"
check  "$V6" 'icmpv6-type 128'                    "v6-only option kept in v6"
check  "$V4" 'comment --comment "a # b"'          "tail with spaces and a hash survives"
check  "$V4" 'log-prefix "TEST LD: "'             "quoted log prefix survives"
check  "$V4" 'dport 9999 -j CFW_+logged'          "jump to a global chain resolves"
check  "$V4" '\-s 198.51.100.99/32'               "inline literal endpoint"
check  "$V4" 'dport 22 -j ACCEPT'                 "input hook reached"
check  "$V4" 'hashlimit-name test_limit'          "backslash continuation is one rule"
check  "$V4" 'dport 25 -j REDIRECT'               "nat target survives the probe"
check  "$V4" 'MASQUERADE'                         "postrouting hook reached"

echo
if [ $FAILED -eq 0 ]; then
	echo "all checks passed"
	exit 0
fi
echo "$FAILED check(s) failed; artifacts in $WORK" 1>&2
exit 1

#!/bin/bash

source fw_vars

[ $TRACE -eq 1 ] && set -x

# Date and echo to stderr combined.
decho () {
	echo -e "[`date '+%b %e %T'`] ${_PROG} $@" 1>>$LOG_SOCKET
}

# Print text depending on whetever DEBUG is set.
debug () {
	[ $DEBUG -eq 1 ] && decho "$@"
	return 0
}

# Print command as they run.
_run () {
	debug "» $@"
	"$@"
}

set_current_ips_version () {
	echo -n "$1" > $IPSET_PREFIX_FILE
}

get_current_ips_version () {
	local last=1

	if [ ! -f $IPSET_PREFIX_FILE ]; then
		set_current_ips_version $last

		$IPSET list -n | sed -r -n -e "s/${FWR}([0-9]+)_.*/\\1/p" | while read line
		do
			if [ $line -gt $last ]; then
				last=$line
				set_current_ips_version $last
			fi
		done
	fi

	cat $IPSET_PREFIX_FILE
}

# Write fail file
_write_fail () {
	[ -d "$CACHEDIR" ] && touch $FAIL
}

# Common usage function.
_fw_usage () {
	_write_fail
	echo "Usage: ${_PROG} $@" 1>&2
	exit 2
}

# Called by scripts when something has failed but it is not fatal yet.
_fw_fail () {
	_write_fail
	decho "line $BASH_LINENO: $@"
}

# Called by scripts when something has failed.
_fw_abort () {
	_write_fail
	decho "line $BASH_LINENO: $@"
	exit 2
}

# If a command fails unexpectedely, return when and where.
_fw_exit_trap () {
	_write_fail
	decho "line $2: Wrong return code [$1], exiting."
	exit $1
}

# Get chains from iptables-save output.
get_chains () {
	sed -r -n -e "s/^:(${1}[^ ]+) .*/\1/p"
}

# Wrapper for _fw_rule
fw_rule () {
	_fw_rule "$0" "$@"
}

# Run a command each iptables table.
# Sets ipt_cur_table to the current table.
ipt_foreach_table () {
	local start_with="$1"; shift
	local V

	for V in 4 6
	do
		eval "IPTABLES=\$IP${V}TABLES"
		eval "IPTABLES_SAVE=\$IP${V}TABLES_SAVE"

		for ipt_cur_table in $IPTABLES_TABLES
		do
			"$@"
		done
	done
}

# Run a command each iptables chain starting with a regex.
# First argument is start_with.
# Sets ipt_cur_table to the current table.
# Sets ipt_cur_chain to the current chain.
ipt_foreach_chain_starting_with () {
	local start_with="$1"; shift
	local V

	for V in 4 6
	do
		eval "IPTABLES=\$IP${V}TABLES"
		eval "IPTABLES_SAVE=\$IP${V}TABLES_SAVE"

		for ipt_cur_table in $IPTABLES_TABLES
		do
			$IPTABLES_SAVE -t $ipt_cur_table | get_chains "$start_with" | sort -n | while read ipt_cur_chain
			do
				[ -z $ipt_cur_chain ] && continue
				"$@"
			done
		done
	done
}

# Executes a command for each existing ipset starting with a regex.
# First argument is start_with.
# Sets ips_cur_set to the current ipset.
ipset_foreach_starting_with () {
	local start_with="$1"; shift

	$IPSET -n list | sed -r -n -e "/^${start_with}/p" | while read ips_cur_set
	do
		"$@"
	done


}

# Used in ipt_foreach_chain_starting_with.
# Uses ipt_cur_table.
# Uses ipt_cur_chain.
modify_chain_builtin () {
	local table=$ipt_cur_table
	local chain=$ipt_cur_chain

	# Check if add or remove.
	case $1 in
		add) local add=1;;
		remove) local add=0;;
	esac
	shift

	# Define what chain we need to modify.
	local builtin_chain=`cut -d'_' -f3 <<< $chain`
	builtin_chain=${builtin_chain^^}

	# Remove (and add) sub-chains.
	$IPTABLES -t $table -D $builtin_chain -j $chain 2>/dev/null || true
	if [ $add -eq 1 ]; then
	   $IPTABLES -t $table -A $builtin_chain -j $chain
   fi
}

# Start failing now.
trap '_fw_exit_trap $? $LINENO' ERR
set -u -o pipefail -o errtrace

# Make sure run dir exists.
[ -d $RUNDIR ] || mkdir $RUNDIR

# Dynamic IPset version.
CURRENT_IPSET_VER=`get_current_ips_version`
LAST_IPSET_VER=$((CURRENT_IPSET_VER-1))
NEXT_IPSET_VER=$((CURRENT_IPSET_VER+1))
export CURRENT_IPSET_VER NEXT_IPSET_VER
export PREFIX_IPSET="${FWR}${NEXT_IPSET_VER}_"
export LAST_PREFIX_IPSET="${FWR}${LAST_IPSET_VER}_"
export CURRENT_PREFIX_IPSET="${FWR}${CURRENT_IPSET_VER}_"

test -x "$SUDO"

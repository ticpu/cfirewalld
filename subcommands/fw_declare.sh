#!/bin/bash
#
# Declaration emitters used when the build helper is active.
#
# fw_rule and fw_alias_* are shell functions here rather than exec'd scripts:
# printf is a builtin, so a declaration costs no process. Fields are NUL
# separated because rule tails contain spaces, quotes and '#'.

# Emit one record on fd 3. $1 is the kind, the rest are its fields.
_fw_declare () {
	local kind="$1"; shift
	printf '%s\0%s\0%s' "$kind" "${BASH_SOURCE[2]##*/}" "${BASH_LINENO[1]}" >&3
	printf '\0%s' "$@" >&3
	printf '\n' >&3
}

fw_rule () {
	_fw_declare rule "$@"
}

fw_alias_ip () {
	_fw_declare alias "$@"
}

fw_alias_dns () {
	_fw_declare alias "$@"
}

fw_alias_host () {
	_fw_declare alias "$@"
}

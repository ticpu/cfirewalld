source subcommands/fw_common.sh

## <Aliases> ##
# Literal v4 and v6 under one name.
fw_alias_host	both_fam		198.51.100.0/24
fw_alias_host	both_fam		2001:db8:1::/64

# Ported set, and the same alias reached through each entry point.
fw_alias_ip		ported_svc		198.51.100.10		443		tcp
fw_alias_ip		ported_svc		2001:db8:1::10		443		tcp

# Port-only bitmap, which needs host `any`.
fw_alias_ip		bare_ports		any					8080	tcp

# Single host, v4 only: rules using it must not appear in the v6 ruleset.
fw_alias_host	v4_only			203.0.113.5

# Single host, v6 only.
fw_alias_host	v6_only			2001:db8:2::5
## </Aliases> ##

## <Rules>
# Both endpoints aliased, both families.
fw_rule filter forward	both_fam	both_fam	-j ACCEPT

# Two-dimensional set: the direction must be emitted twice.
fw_rule filter forward	any			ported_svc	-j ACCEPT

# Port bitmap.
fw_rule filter forward	any			bare_ports	-p tcp -j ACCEPT

# Family-confined by alias, not by syntax.
fw_rule filter forward	v4_only		any			-j ACCEPT
fw_rule filter forward	v6_only		any			-j ACCEPT

# Family-confined by an option the other family rejects.
fw_rule filter forward	any			any			-p icmp --icmp-type echo-request -j ACCEPT
fw_rule filter forward	any			any			-p icmpv6 --icmpv6-type echo-request -j ACCEPT

# A tail carrying spaces, quotes and a '#'.
fw_rule filter forward	any			any			-m comment --comment "a # b" -j ACCEPT
fw_rule filter +logged	any			any			-m limit --limit 1/sec -j LOG --log-prefix "TEST LD: "

# Jump to a global chain, and the global chain itself.
fw_rule filter forward	any			any			-p tcp --dport 9999 -j +logged
fw_rule filter +logged	any			any			-j DROP

# A literal endpoint written inline rather than via an alias.
fw_rule filter forward	198.51.100.99	any		-j ACCEPT

# Hooks other than forward.
fw_rule filter input	any			any			-p tcp --dport 22 -j ACCEPT
fw_rule filter output	any			any			-j ACCEPT

# A table other than filter, whose target only exists there.
fw_rule nat prerouting	any			any			-p tcp --dport 25 -j REDIRECT
fw_rule nat postrouting	any			any			-o eth0 -j MASQUERADE

# Backslash continuation.
fw_rule filter forward	any			any			-m hashlimit \
	--hashlimit-upto 8/min --hashlimit-burst 32 \
	--hashlimit-mode srcip --hashlimit-name test_limit -j ACCEPT
## </Rules>

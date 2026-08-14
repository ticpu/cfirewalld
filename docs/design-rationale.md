# Design rationale

## Two resident rulesets, switched by a jump

The new ruleset is built under a `CFWTMP_` prefix while the live `CFW_` one keeps
serving traffic. Nothing switches until the jump from the built-in chain is moved
(`modify_chain_builtin`). This is what makes rollback re-pointing a jump at chains
already in the kernel rather than rebuilding anything.

The new delegate is appended to the built-in *before* the old one is removed. The
old ruleset therefore sits ahead of the new one and still reaches a terminal target
for every packet it would have decided; the new ruleset takes effect only when the
old jump is deleted. Reversing the order opens a window with neither ruleset in the
path.

## Rollback depends on nothing outside the kernel

Rollback runs when something is already broken, so it must not be able to fail for
an external reason. Re-applying a saved ruleset would break this twice: hostnames
are resolved at build time, so a snapshot holds frozen addresses rather than intent,
and a ruleset load is all-or-nothing, so one entry that no longer validates takes
the whole rollback with it.

This is also why ipsets are versioned by prefix instead of renamed: the old sets
must stay live for the old chains to keep matching.

## A failed build is inert

`CFWTMP_` chains are unreferenced until the switch, so a build that dies partway
leaves the live ruleset in charge and the partial work affecting no traffic. Recovery
is to fix the config and re-run; the next reload clears the leftovers. Any
replacement for the build path has to preserve this: generate only into `CFWTMP_`,
and never flush a table.

## Rule tails are opaque

Everything after the source and destination is passed through to iptables unparsed.
Configs use service names, `hashlimit`, `multiport`, `comment` and port ranges, so
anything that interprets the tail signs up to track the whole iptables match
vocabulary. The build path may reorder nothing and rewrite only `-j +chain` targets.

## Family is decided by alias, not by match syntax

Both iptables and ip6tables accept protocol matches belonging to the other family —
`-p icmpv6` is accepted on IPv4 and `-p icmp` on IPv6. Only an unknown *option*
(`--icmp-type` under ip6tables) is rejected. Family therefore cannot be inferred
from the tail, and a rule is confined to a family only by an alias that exists for
that family alone.

Rules whose endpoints are all literals or `any` are emitted for both families and
kept where the load succeeds. A rule that names a family-specific protocol without a
family-specific alias is installed on both, where the wrong one matches nothing.

## Hostnames appearing directly in rules

A source or destination containing a dot is passed to iptables as a literal, which
resolves it and expands one declaration into one rule per address. Aliases resolve
the same names into sets instead. Both paths exist; a name used directly in a rule
is not interchangeable with an alias holding the same name.

## Resolution happens once per name, before anything is submitted

Every name in the config — alias hosts and hostnames used directly in rules — is
resolved in a single pass before any set or rule is built. A name used by several
aliases yields one answer, so rotating pools cannot make two aliases disagree, and a
resolution failure aborts while nothing has been submitted.

The failure must name the alias and the hostname. Reporting it downstream, as a rule
referring to a set that was never created, sends the reader hunting through the
ruleset for a DNS problem.

## Set construction is concurrent, rule construction is ordered

Sets are independent of each other and their cost is DNS latency, so they are built
concurrently. Rules are not: order within a chain is the policy, since the first
terminal match wins. Rule generation is sequential and deterministic so that
generated output can be diffed against a previous run.

Sets must be submitted before rules, and a failure in the set phase must stop the
rule phase — rules reference sets by name.

## iptables addresses the nft backend

Targets run `iptables` built on `nf_tables`, so a ruleset load fetches and commits
the whole ruleset rather than appending cheaply. This bounds how many separate loads
are worth doing, and it means moving to native nft syntax would be a change of rule
language, not of backend.

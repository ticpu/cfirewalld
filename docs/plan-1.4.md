# 1.4 — Rust build helper

Replace the per-rule shell fork storm with a single helper that resolves DNS
concurrently and submits sets and rules through `ipset restore` and
`iptables-restore --noflush`. The switch, rollback, commit and cleanup stay in
bash; only the build phase moves.

Design constraints live in `docs/design-rationale.md` — read it before changing
anything here.

## Measured baseline

`cadevrtr1`, Debian 12, 2 cores, 138 `fw_rule` and 211 `fw_alias_host`
declarations. Timed as:

    time (sh -c 'echo $$'; yes n | ./fw_reload >/dev/null 2>&1; sh -c 'echo $$')

| run | wall | PIDs spawned |
|---|---|---|
| normal ×3 | 29.9s, 30.3s, 29.7s | 13,747 / 13,640 / 13,570 |
| stubbed DNS ×2 | 22.4s, 24.1s | 12,999 / 13,716 |

- ~2.20 ms per process; ~13,650 processes per reload.
- DNS is ~6.7s, ~22% of wall. Process counts are the same stubbed or not, so this
  is resolver latency, not extra fan-out.
- `user`+`sys` ≈ `real` on 2 cores: fork/exec bound, so removing forks converts
  almost linearly into wall time.

Projection: bashisms alone ~20s (DNS floor untouched); helper ~1-2s.

Achieved, same host and config: **691 processes, 5.3s** — 20x fewer processes,
5.7x faster. `user`+`sys` is 1.8s of that 5.3s, so it is no longer fork-bound;
the remainder is conntrackd's stop, `sleep 1` and start.

DNS stub used for the measurement, as `/etc/cfirewalld/dig-stub` with
`export DIG="_run /etc/cfirewalld/dig-stub"` in `fw_vars`:

    #!/bin/sh
    case "$2" in
        a|A) echo "192.0.2.1" ;;
        aaaa|AAAA) echo "2001:db8::1" ;;
    esac

## Where the forks are

Per rule (~30), in `_fw_rule`: the exec itself, `source fw_common.sh`, the
`$(echo|sed)` chain name, `ipset_direction`'s `ipset list | egrep | tr | wc` per
aliased endpoint, `seq`, four backtick subshells for `alias_to_iptables`, `cat`
on the error log, and two `iptables` calls. The rest is the alias path: one
`fw_alias_ip` per resolved address, each sourcing `fw_common.sh` and running
`ipset create` plus `ipset add` through `_run`, with `date` on every `_run`.

## Architecture

    firewall.d/*.sh          fw_rule / fw_alias_* become shell functions
      │                      that printf to fd 3 (builtin, no fork)
      ▼ fd 3, closed at EOF
    cfw-build                one process
      │ parse declarations
      │ resolve every unique name concurrently
      │ ── barrier: any failure aborts, nothing submitted
      │ build sets            → ipset restore
      │ ── barrier: non-zero exit aborts
      │ build rules, grouped by chain, ordered by file/line
      ▼                      → iptables-restore --noflush ×2 (v4, v6)
    fw_reload                resumes at fw_prepare_zones / fw_apply

Target ~20-30 processes per reload.

## Verified target behaviour

On `cadevrtr1` (Debian 12, iptables 1.8.9, nf_tables backend):

- `:CHAIN - [0:0]` inside a `--noflush` load **flushes that chain**, on both the
  nft and legacy backends. Each `CFWTMP_` chain must therefore be emitted exactly
  once per load with all its rules. Chains like `+reject` and `+inet_or_reject`
  collect rules from several config files, so grouping by chain across the whole
  config is required — declarations cannot be streamed straight through.
- `--noflush` re-declaration works on both backends, so no version gate is needed
  beyond iptables 1.8.
- `iptables-translate` cannot type families: `-p icmpv6` translates cleanly under
  IPv4 and `-p icmp` under IPv6. Real iptables barely discriminates either — only
  an unknown option such as `--icmp-type` under ip6tables fails. Useless as a
  validator; a fork per rule if used anyway.

## Declaration shapes in production config

From `/etc/cfirewalld/firewall.d/` on cadevrtr1:

- only `fw_alias_host` is used; `fw_alias_ip` and `fw_alias_dns` are reached
  through it
- alias arity 2, 3 or 5 (name + host, + port, + port + proto)
- tabs and spaces mixed as separators; trailing `#comment` after arguments
- backslash line continuations in rule tails
- one alias name taking both v4 and v6 CIDRs
- bare FQDNs as rule endpoints (~20), resolved by iptables itself
- tails using `--dport whois`, `-m hashlimit`, `-m multiport`, `-m comment`, port
  ranges, `-j +chain`, and nat/prerouting/REDIRECT
- two rules deliberately sharing `--hashlimit-name dhcpv6_queries`

## Steps

1. `docs/design-rationale.md`, `debian/control`, README — done.
2. Declaration format and parser, with the production config as fixtures.
3. Concurrent resolver over all unique names.
4. `ipset restore` emitter; set dimensions known at construction, replacing
   `ipset_direction`.
5. `iptables-restore` emitter, grouped by chain.
6. `fw_rule` / `fw_alias_*` become shell functions writing to fd 3; `fw_reload`
   prefers the helper, falls back to bash when absent or when `CFW_HELPER=0`.
   Done, installed on cadevrtr1 from the package.
7. Clean up the config's dead DNS names — 24 of them, reported with file and
   line by a reload. Blocks step 8: sets and rules cannot be exercised until
   resolution passes.
8. Validate on cadevrtr1: same host, same config, flip `CFW_HELPER`, diff
   `iptables-save` and `ipset save`.

## Accepted divergence

Bare-FQDN rule endpoints are resolved by the helper instead of by iptables, so one
declaration may expand into a different number of rules than before. Validation
expects differences only in those rules, and checks each expansion against the
addresses iptables would have produced.

## Found in production

The config carries 24 alias hostnames that no longer resolve, across three
files. 1.3 created no set for them and said nothing, so a rule referencing one
failed later with `set CFWTMP_… not found` — and an alias no rule referenced
failed invisibly. This is the accumulation the abort exists to stop.

`fw_reload` leaked one `tail -f` per run: the kill sat after the apply step, so
every rollback and abort left one following a deleted socket. Fixed in the exit
trap.

## Deferred


- The conntrackd stop/start around a reload, with its `sleep 1`, is now most of
  the wall time.
- `get_current_ips_version` (`fw_common.sh:34-40`) updates `last` inside a
  pipeline subshell, so the comparison never persists to the parent. Correctness
  bug, unrelated to performance.
- An explicit family marker on `fw_rule`, so `-p icmpv6` rules stop being
  installed on IPv4 where they match nothing. Behaviour change; not 1.4.

# cfirewalld

BASH firewall over iptables/ip6tables/ipset. Entry point `fw_reload`; verbs in
`subcommands/`, found via `PATH` (`fw_vars:26`). User rules in `firewall.d/*.sh`
call `fw_rule` / `fw_alias_*`.

Read `docs/design-rationale.md` before changing the apply path. 1.4 work in
progress: `docs/plan-1.4.md`.

## Invariants

- Never touch `CFW_` while building — new work goes only into `CFWTMP_`, and no
  code path may flush a table. A failed build has to stay inert.
- Rollback is a jump toggle between two resident rulesets, not a re-apply. It must
  not depend on DNS, on re-validation, or on anything outside the kernel.
- Old and new ipsets coexist by version prefix; the old ones stay live because the
  old chains reference them.
- Rule tails after SOURCE/DESTINATION are opaque. Pass them through; rewrite only
  `-j +chain`.
- A `:CHAIN - [0:0]` line flushes that chain even under
  `iptables-restore --noflush`. Emit each chain once per load, with all its rules.
- iptables chain names must be under 29 characters. `CFWTMP_` plus the longest
  generated name currently reaches 27, so the prefix has almost no slack — a
  longer prefix or a longer config filename overflows it. Test prefixes must be
  the same length as the real one or the limit is hit spuriously.

## Traps

- Always build the helper with `./build-helper.sh`, never a bare `cargo build`.
  The container pins the glibc floor at 2.30; a natively built one carries the
  build machine's, and refuses to start on anything older. `objdump -T cfw-build
  | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1` shows the floor.
- Integration tests need `NET_ADMIN` **and** `NET_RAW`. With only the first,
  ipset works and every rule referencing a set silently fails to install.
- Alias names must not contain `.` or `:` — `alias_to_iptables` (`_fw_rule:70`)
  uses those to tell a literal address from an alias. A rule endpoint containing a
  dot is handed to iptables as a hostname for it to resolve.
- `fw_cleanup` disables `pipefail` deliberately (`fw_cleanup:15`).
- `CACHEDIR`, `COMMIT_FILE` and `LOG_SOCKET` live under `/tmp` (`fw_vars:12-21`);
  a reboot mid-commit loses the resume marker.
- Targets run iptables on the nf_tables backend, so every restore invocation
  commits the whole ruleset. Few loads, not many.

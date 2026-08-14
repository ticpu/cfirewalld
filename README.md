# cfirewalld

This BASH based firewall was invented with 3 main things in mind.
* Be able to resolve DNS correctly and, in the future, automatically update
  those entry for internal DNS servers like pfSense.
* Integrate IPv4 and IPv6 since no one wants to manage 2 different firewalls
  for the same purpose.
* Atomically apply firewalls and test them before committing like Juniper
  `commit confirm`.

Since this is a BASH script-based firewall, it is currently quite slow and
spawn almost 5000 processes for a about 50 rules. Rewritting the whole thing
in Python might be a good idea since when I started, another goal was to keep
it relatively simple so any sysadmin could diagnose the script since it is
BASH.

However, after adding many sanity test, it ended using much more compli-
cated BASH-only features which would be better represented in a fully-featured
programming language. Also, using iptables library would help speed very much.

## Requirements

iptables 1.8 or later, ipset, dig, sudo and systemd. Either iptables backend
works; the nf_tables one is what 1.4 is tested against.

From 1.4 the build phase runs in a Rust helper. `./build-helper.sh [x86_64|aarch64]`
builds it in a container, so the build host needs only podman or docker. It is
compiled against bullseye and runs on Debian 11 and Ubuntu 20.04 or newer.

Where the helper is missing, or when `CFW_HELPER=0` is set in `fw_vars`,
`fw_reload` falls back to the BASH implementation, which stays supported.

## TODO
- [x] Basic functionnality.
- [ ] Automatic name resolve as system service.
- [ ] Documentation for firewall functions.
- [ ] Speed optimisation.

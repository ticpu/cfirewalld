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

## TODO
- [x] Basic functionnality.
- [ ] Automatic name resolve as system service.
- [ ] Documentation for firewall functions.
- [ ] Speed optimisation.

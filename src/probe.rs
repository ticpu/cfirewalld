//! Which families accept a rule tail.
//!
//! A tail is offered to each family's binary in a scratch chain. Only an option
//! belonging to the other family is rejected, so this catches exactly what the
//! shell's try-both caught, at one probe per distinct tail rather than per rule.

use std::collections::{HashMap, HashSet};
use std::process::Command;

use crate::sets::Family;

/// Chain the probe appends to. Created and removed around the run, and never
/// referenced, so a probe that fails partway affects no traffic.
const PROBE_CHAIN: &str = "CFWPROBE";

pub struct Prober {
    /// Keyed by table and tail: a target valid in one table is rejected in
    /// another, so REDIRECT probed in filter would drop a nat rule entirely.
    cache: HashMap<(String, Vec<String>), Vec<Family>>,
    /// Tables the scratch chain has been created in.
    prepared: HashSet<String>,
    /// Set when the scratch chain could not be created; every tail is then
    /// offered to both families, which is what the shell did.
    degraded: bool,
}

fn binary(family: Family) -> &'static str {
    match family {
        Family::V4 => "iptables",
        Family::V6 => "ip6tables",
    }
}

impl Prober {
    pub fn new() -> Self {
        Prober {
            cache: HashMap::new(),
            prepared: HashSet::new(),
            degraded: false,
        }
    }

    /// Create the scratch chain in one table, once per run.
    fn prepare(&mut self, table: &str) {
        if self.prepared.contains(table) {
            return;
        }
        self.prepared.insert(table.to_string());

        for family in [Family::V4, Family::V6] {
            // Already existing is fine; anything else means probing is not
            // available and the caller falls back to offering both families.
            let status = Command::new(binary(family))
                .args(["-t", table, "-N", PROBE_CHAIN])
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(_) => {
                    // -N fails when the chain exists, which is harmless; flush
                    // it so a previous run's contents cannot confuse a probe.
                    let flushed = Command::new(binary(family))
                        .args(["-t", table, "-F", PROBE_CHAIN])
                        .status();
                    if !matches!(flushed, Ok(s) if s.success()) {
                        self.degraded = true;
                    }
                }
                Err(e) => {
                    eprintln!("cfw-build: cannot run {}: {e}", binary(family));
                    self.degraded = true;
                }
            }
        }
    }

    /// Families whose binary accepts this tail in this table.
    pub fn families_for(&mut self, table: &str, tail: &[String]) -> Vec<Family> {
        let key = (table.to_string(), tail.to_vec());
        if let Some(hit) = self.cache.get(&key) {
            return hit.clone();
        }

        self.prepare(table);
        if self.degraded {
            return vec![Family::V4, Family::V6];
        }

        let accepted: Vec<Family> = [Family::V4, Family::V6]
            .into_iter()
            .filter(|f| self.accepts(*f, table, tail))
            .collect();

        self.cache.insert(key, accepted.clone());
        accepted
    }

    fn accepts(&self, family: Family, table: &str, tail: &[String]) -> bool {
        let appended = Command::new(binary(family))
            .args(["-t", table, "-A", PROBE_CHAIN])
            .args(tail)
            .output();

        match appended {
            Ok(out) if out.status.success() => {
                // Leave the chain empty for the next probe.
                let _ = Command::new(binary(family))
                    .args(["-t", table, "-D", PROBE_CHAIN])
                    .args(tail)
                    .output();
                true
            }
            Ok(_) => false,
            Err(e) => {
                eprintln!("cfw-build: probing {}: {e}", binary(family));
                false
            }
        }
    }

    /// Remove the scratch chain from every table it was created in.
    pub fn cleanup(&self) {
        for table in &self.prepared {
            for family in [Family::V4, Family::V6] {
                for args in [["-F", PROBE_CHAIN], ["-X", PROBE_CHAIN]] {
                    if let Err(e) = Command::new(binary(family))
                        .args(["-t", table])
                        .args(args)
                        .status()
                    {
                        eprintln!(
                            "cfw-build: removing probe chain via {}: {e}",
                            binary(family)
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs root and real iptables, so it is not part of the default run.
    #[test]
    #[ignore]
    fn family_specific_options_are_rejected_by_the_other_family() {
        let mut p = Prober::new();

        let v6_only: Vec<String> = ["-p", "icmpv6", "--icmpv6-type", "echo-request", "-j", "DROP"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(p.families_for("filter", &v6_only), vec![Family::V6]);

        let v4_only: Vec<String> = ["-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(p.families_for("filter", &v4_only), vec![Family::V4]);

        let both: Vec<String> = ["-p", "tcp", "-j", "ACCEPT"].iter().map(|s| s.to_string()).collect();
        assert_eq!(p.families_for("filter", &both), vec![Family::V4, Family::V6]);

        p.cleanup();
    }
}

//! Set construction and the `ipset restore` stream.
//!
//! A set's dimension is known here, where it is created, so rules can emit
//! `src` or `src,src` without interrogating ipset for each address.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::decl::{Alias, Decl};
use crate::resolve::{classify, Host, Resolved};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn ipset_keyword(self) -> &'static str {
        match self {
            Family::V4 => "inet",
            Family::V6 => "inet6",
        }
    }

    pub fn of(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    /// A literal is v6 if it carries a colon, matching the shell's test.
    pub fn of_literal(literal: &str) -> Self {
        if literal.contains(':') {
            Family::V6
        } else {
            Family::V4
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SetType {
    /// hash:net — addresses only.
    Net,
    /// hash:net,port — addresses with a port.
    NetPort,
    /// bitmap:port — ports only, for a host of `any`.
    Port,
}

impl SetType {
    /// How many match directions a rule must emit for this set.
    pub fn dimensions(self) -> usize {
        match self {
            SetType::Net | SetType::Port => 1,
            SetType::NetPort => 2,
        }
    }

    fn create_args(self, family: Family) -> String {
        match self {
            SetType::Net => format!("hash:net family {} counters", family.ipset_keyword()),
            SetType::NetPort => format!("hash:net,port family {} counters", family.ipset_keyword()),
            SetType::Port => "bitmap:port range 1-65535 counters".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct Set {
    pub name: String,
    pub family: Family,
    pub set_type: SetType,
    /// Entries as ipset spells them, in declaration order.
    pub entries: Vec<String>,
}

/// Sets keyed by their unprefixed name, so a rule can look up the dimension and
/// whether a family exists for a given alias.
#[derive(Debug, Default)]
pub struct Sets {
    pub by_name: BTreeMap<String, Set>,
}

impl Sets {
    /// The set name as it appears in a rule: `_v6` suffix for the v6 half.
    pub fn set_name(alias: &str, family: Family) -> String {
        match family {
            Family::V4 => alias.to_string(),
            Family::V6 => format!("{alias}_v6"),
        }
    }

    /// A port bitmap carries no family and exists only under the bare name, so
    /// a v6 rule referencing one finds nothing and is not emitted. The rule
    /// would be valid — the bitmap matches either family — but the shell drops
    /// it for want of a `_v6` set, and a reload must not start matching traffic
    /// it did not match before.
    pub fn get(&self, alias: &str, family: Family) -> Option<&Set> {
        self.by_name.get(&Self::set_name(alias, family))
    }

    /// A set's type is fixed when ipset creates it, so an alias that mixes
    /// ported and unported hosts cannot be represented.
    fn entry_for(
        &mut self,
        alias: &str,
        family: Family,
        set_type: SetType,
    ) -> Result<&mut Set, SetType> {
        let name = Self::set_name(alias, family);
        let set = self.by_name.entry(name.clone()).or_insert_with(|| Set {
            name,
            family,
            set_type,
            entries: Vec::new(),
        });
        if set.set_type != set_type {
            return Err(set.set_type);
        }
        Ok(set)
    }
}

/// A port spec as ipset wants it: `proto:port`, defaulting to tcp like the shell.
fn port_spec(port: &str, proto: Option<&str>) -> String {
    match proto {
        Some(p) if p.len() == 3 => format!("{p}:{port}"),
        _ => port.to_string(),
    }
}

#[derive(Debug)]
pub struct BuildError {
    pub message: String,
}

/// ipset refuses a name over this length. The budget an alias actually gets is
/// smaller: the versioned prefix grows a character every tenfold increase, and
/// the v6 half of a pair carries a suffix.
const IPSET_NAME_MAX: usize = 31;

/// Reject a name ipset will refuse, naming the alias rather than letting the
/// restore stream fail partway with the assembled name.
fn check_name_length(
    alias: &str,
    prefix: &str,
    origin: &crate::decl::Origin,
) -> Result<(), BuildError> {
    // The v6 suffix is what makes the pair's longer half; check that one.
    let longest = format!("{prefix}{alias}_v6").len();
    if longest > IPSET_NAME_MAX {
        return Err(BuildError {
            message: format!(
                "alias {alias} at {origin}: {longest} characters with the set prefix and the v6 \
                 suffix, over ipset's limit of {IPSET_NAME_MAX} — shorten the alias by {} \
                 character(s)",
                longest - IPSET_NAME_MAX
            ),
        });
    }
    Ok(())
}

/// `_v6` is how the v6 half of every alias is named, in one namespace with the
/// aliases themselves, so an alias spelled that way claims the v6 set of its own
/// stem. Naming a v6-only alias for its family collides the same way as a stem
/// that exists: both end up in one set holding both families' entries, which v4
/// rules then match.
fn check_name_suffix(alias: &str, origin: &crate::decl::Origin) -> Result<(), BuildError> {
    if let Some(stem) = alias.strip_suffix("_v6") {
        return Err(BuildError {
            message: format!(
                "alias {alias} at {origin}: _v6 is the suffix given to the v6 half of alias \
                 {stem}, so it cannot be written by hand — name this one {stem}, which holds \
                 whichever families its addresses belong to"
            ),
        });
    }
    Ok(())
}

fn mixed(name: &str, origin: &crate::decl::Origin, had: SetType, got: SetType) -> BuildError {
    BuildError {
        message: format!(
            "alias {name} at {origin}: already built as {had:?}, cannot also hold {got:?} \
             entries — an alias is either all ported or all unported"
        ),
    }
}

/// Build every set from the alias declarations and the resolved names.
///
/// `prefix` is only used to reject a name ipset would refuse; it is applied at
/// render time, not stored.
pub fn build(decls: &[Decl], resolved: &Resolved, prefix: &str) -> Result<Sets, BuildError> {
    let mut sets = Sets::default();

    // Every unusable name at once: each costs a reload to discover otherwise,
    // and on a remote host that is the whole diagnosis.
    let mut rejected = Vec::new();
    for decl in decls {
        let Decl::Alias(Alias { name, origin, .. }) = decl else {
            continue;
        };
        for check in [
            check_name_length(name, prefix, origin),
            check_name_suffix(name, origin),
        ] {
            if let Err(e) = check {
                rejected.push(e.message);
            }
        }
    }
    if !rejected.is_empty() {
        return Err(BuildError {
            message: format!(
                "{} unusable alias name(s):\n  {}",
                rejected.len(),
                rejected.join("\n  ")
            ),
        });
    }

    for decl in decls {
        let Decl::Alias(Alias {
            name,
            host,
            port,
            proto,
            origin,
        }) = decl
        else {
            continue;
        };

        let port_field = port.as_ref().map(|p| port_spec(p, proto.as_deref()));

        match classify(host) {
            Host::Any => {
                // `any` with a port is a port-only set; without one it would
                // match everything, which the shell has no representation for.
                let Some(spec) = &port_field else {
                    return Err(BuildError {
                        message: format!("alias {name} at {origin}: host 'any' needs a port"),
                    });
                };
                // A port bitmap carries no family and takes no _v6 name: one
                // set serves both, and rules of either family match it.
                let set = sets
                    .entry_for(name, Family::V4, SetType::Port)
                    .map_err(|had| mixed(name, origin, had, SetType::Port))?;
                set.entries.push(spec.clone());
            }
            Host::Literal(literal) => {
                let family = Family::of_literal(&literal);
                let set_type = if port_field.is_some() {
                    SetType::NetPort
                } else {
                    SetType::Net
                };
                let entry = match &port_field {
                    Some(spec) => format!("{literal},{spec}"),
                    None => literal.clone(),
                };
                sets.entry_for(name, family, set_type)
                    .map_err(|had| mixed(name, origin, had, set_type))?
                    .entries
                    .push(entry);
            }
            Host::Name(dns) => {
                for addr in resolved.get(&dns) {
                    let family = Family::of(addr);
                    let set_type = if port_field.is_some() {
                        SetType::NetPort
                    } else {
                        SetType::Net
                    };
                    let entry = match &port_field {
                        Some(spec) => format!("{addr},{spec}"),
                        None => addr.to_string(),
                    };
                    sets.entry_for(name, family, set_type)
                        .map_err(|had| mixed(name, origin, had, set_type))?
                        .entries
                        .push(entry);
                }
            }
        }
    }

    Ok(sets)
}

/// Render the `ipset restore` stream. `prefix` is the versioned set prefix.
pub fn render(sets: &Sets, prefix: &str) -> String {
    let mut out = String::new();

    for set in sets.by_name.values() {
        let name = format!("{prefix}{}", set.name);
        let _ = writeln!(
            out,
            "create {name} {}",
            set.set_type.create_args(set.family)
        );
        for entry in &set.entries {
            let _ = writeln!(out, "add {name} {entry}");
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::parse;
    use crate::resolve::Resolved;
    use std::collections::BTreeMap;

    fn rec(fields: &[&str]) -> String {
        format!("{}\n", fields.join("\0"))
    }

    fn resolved(pairs: &[(&str, &[&str])]) -> Resolved {
        let mut addrs = BTreeMap::new();
        for (name, list) in pairs {
            addrs.insert(
                name.to_string(),
                list.iter().map(|a| a.parse().unwrap()).collect(),
            );
        }
        Resolved { addrs }
    }

    fn build_from(input: &str, r: &Resolved) -> Sets {
        build(&parse(input).unwrap(), r, "CFW_N_").unwrap()
    }

    #[test]
    fn net_set_has_one_dimension_and_netport_has_two() {
        let input = rec(&["alias", "a.sh", "1", "plain", "10.0.0.0/8"])
            + &rec(&["alias", "a.sh", "2", "ported", "10.0.0.0/8", "53", "udp"]);
        let sets = build_from(&input, &resolved(&[]));
        assert_eq!(
            sets.get("plain", Family::V4).unwrap().set_type.dimensions(),
            1
        );
        assert_eq!(
            sets.get("ported", Family::V4)
                .unwrap()
                .set_type
                .dimensions(),
            2
        );
    }

    #[test]
    fn v6_literal_lands_in_the_v6_set() {
        let input = rec(&["alias", "a.sh", "1", "net", "10.10.255.32/28"])
            + &rec(&["alias", "a.sh", "2", "net", "fd51:2050:2220:502::/64"]);
        let sets = build_from(&input, &resolved(&[]));
        assert_eq!(
            sets.get("net", Family::V4).unwrap().entries,
            ["10.10.255.32/28"]
        );
        assert_eq!(
            sets.get("net", Family::V6).unwrap().entries,
            ["fd51:2050:2220:502::/64"]
        );
        assert_eq!(sets.get("net", Family::V6).unwrap().name, "net_v6");
    }

    #[test]
    fn a_name_fans_out_into_both_families() {
        let input = rec(&[
            "alias",
            "a.sh",
            "1",
            "svc",
            "host.example.test",
            "53",
            "udp",
        ]);
        let r = resolved(&[("host.example.test", &["192.0.2.1", "2001:db8::1"])]);
        let sets = build_from(&input, &r);
        assert_eq!(
            sets.get("svc", Family::V4).unwrap().entries,
            ["192.0.2.1,udp:53"]
        );
        assert_eq!(
            sets.get("svc", Family::V6).unwrap().entries,
            ["2001:db8::1,udp:53"]
        );
    }

    #[test]
    fn multiple_addresses_all_become_entries() {
        let input = rec(&["alias", "a.sh", "1", "pool", "pool.example.test"]);
        let r = resolved(&[(
            "pool.example.test",
            &["192.0.2.1", "192.0.2.2", "192.0.2.3"],
        )]);
        let sets = build_from(&input, &r);
        assert_eq!(sets.get("pool", Family::V4).unwrap().entries.len(), 3);
    }

    #[test]
    fn port_defaults_to_bare_when_no_proto() {
        let input = rec(&["alias", "a.sh", "1", "svc", "10.0.0.1", "8200"]);
        let sets = build_from(&input, &resolved(&[]));
        assert_eq!(
            sets.get("svc", Family::V4).unwrap().entries,
            ["10.0.0.1,8200"]
        );
    }

    #[test]
    fn any_with_a_port_is_a_port_bitmap() {
        let input = rec(&["alias", "a.sh", "1", "ports", "any", "443", "tcp"]);
        let sets = build_from(&input, &resolved(&[]));
        let set = sets.get("ports", Family::V4).unwrap();
        assert_eq!(set.set_type, SetType::Port);
        assert_eq!(set.entries, ["tcp:443"]);
    }

    #[test]
    fn a_port_bitmap_is_one_set_reached_only_from_v4() {
        let input = rec(&["alias", "a.sh", "1", "ports", "any", "443", "tcp"]);
        let sets = build_from(&input, &resolved(&[]));
        // One set, named without the _v6 suffix. A v6 rule finds nothing, which
        // is what the shell does, so no rule appears where none did before.
        assert_eq!(sets.by_name.len(), 1);
        assert_eq!(sets.get("ports", Family::V4).unwrap().name, "ports");
        assert!(sets.get("ports", Family::V6).is_none());
    }

    #[test]
    fn an_alias_ending_in_v6_collides_with_the_v6_half_of_its_stem() {
        let input = rec(&["alias", "a.sh", "1", "lan", "fd00::/64"])
            + &rec(&["alias", "a.sh", "2", "lan_v6", "10.0.0.0/8"]);
        let e = build(&parse(&input).unwrap(), &resolved(&[]), "CFW_N_").unwrap_err();
        assert!(e.message.contains("lan_v6"), "{}", e.message);
    }

    #[test]
    fn every_unusable_name_is_reported_in_one_pass() {
        let input = rec(&["alias", "a.sh", "1", "lan_v6", "10.0.0.0/8"])
            + &rec(&["alias", "b.sh", "7", "wan_v6", "10.1.0.0/16"]);
        let e = build(&parse(&input).unwrap(), &resolved(&[]), "CFW_N_").unwrap_err();
        assert!(e.message.contains("2 unusable"), "{}", e.message);
        assert!(e.message.contains("a.sh:1"), "{}", e.message);
        assert!(e.message.contains("b.sh:7"), "{}", e.message);
    }

    #[test]
    fn an_alias_too_long_for_ipset_is_rejected_by_name() {
        // 21 characters: with "CFW_102_" and "_v6" that is 32, one over.
        let input = rec(&["alias", "a.sh", "1", "a-quite-long-alias-nm", "10.0.0.1"]);
        let e = build(&parse(&input).unwrap(), &resolved(&[]), "CFW_102_").unwrap_err();
        assert!(
            e.message.contains("shorten the alias by 1"),
            "{}",
            e.message
        );
    }

    #[test]
    fn the_budget_shrinks_as_the_version_grows() {
        // The same alias fits under a shorter prefix and not under a longer one.
        let input = rec(&["alias", "a.sh", "1", "twenty-char-alias-nm", "10.0.0.1"]);
        let decls = parse(&input).unwrap();
        assert!(build(&decls, &resolved(&[]), "CFW_102_").is_ok());
        assert!(build(&decls, &resolved(&[]), "CFW_10200_").is_err());
    }

    #[test]
    fn any_without_a_port_is_rejected() {
        let input = rec(&["alias", "a.sh", "1", "bad", "any"]);
        let e = build(&parse(&input).unwrap(), &resolved(&[]), "CFW_N_").unwrap_err();
        assert!(e.message.contains("needs a port"));
    }

    #[test]
    fn render_emits_create_then_adds() {
        let input = rec(&["alias", "a.sh", "1", "net", "10.0.0.0/8"])
            + &rec(&["alias", "a.sh", "2", "net", "10.1.0.0/16"]);
        let sets = build_from(&input, &resolved(&[]));
        let out = render(&sets, "CFW_61_");
        assert_eq!(
            out,
            "create CFW_61_net hash:net family inet counters\n\
             add CFW_61_net 10.0.0.0/8\n\
             add CFW_61_net 10.1.0.0/16\n"
        );
    }

    #[test]
    fn mixing_ported_and_unported_in_one_alias_is_rejected() {
        let input = rec(&["alias", "a.sh", "1", "svc", "10.0.0.1", "53", "udp"])
            + &rec(&["alias", "a.sh", "2", "svc", "10.0.0.2"]);
        let e = build(&parse(&input).unwrap(), &resolved(&[]), "CFW_N_").unwrap_err();
        assert!(
            e.message.contains("all ported or all unported"),
            "{}",
            e.message
        );
    }

    #[test]
    fn a_name_resolving_to_one_family_makes_only_that_set() {
        let input = rec(&["alias", "a.sh", "1", "v4only", "legacy.example.test"]);
        let r = resolved(&[("legacy.example.test", &["192.0.2.9"])]);
        let sets = build_from(&input, &r);
        assert!(sets.get("v4only", Family::V4).is_some());
        assert!(sets.get("v4only", Family::V6).is_none());
    }
}

#[cfg(test)]
mod production_fixture {
    use super::*;
    use crate::decl::parse;
    use crate::resolve::{names_to_resolve, Resolved};
    use std::collections::BTreeMap;

    /// Render the real config with every name resolved to fixed addresses, so
    /// the output is stable and can be replayed through ipset restore.
    #[test]
    #[ignore]
    fn render_production_sets() {
        let input = std::fs::read_to_string("scratch/decls-b2e9.txt").expect("fixture missing");
        let decls = parse(&input).unwrap();

        let mut addrs = BTreeMap::new();
        for name in names_to_resolve(&decls).keys() {
            addrs.insert(
                name.clone(),
                vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            );
        }

        let sets =
            build(&decls, &Resolved { addrs }, "CFWPRB_").expect("production config must build");
        let out = render(&sets, "CFWPRB_");
        std::fs::write("scratch/ipset-restore-b2e9.txt", &out).unwrap();
        println!("{} sets, {} lines", sets.by_name.len(), out.lines().count());
    }
}

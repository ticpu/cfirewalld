//! Set construction and the `ipset restore` stream.
//!
//! A set's dimension is known here, where it is created, so rules can emit
//! `src` or `src,src` without interrogating ipset for each address.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::decl::{Alias, Decl};
use crate::resolve::{classify, Host, Resolved};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

fn mixed(name: &str, origin: &crate::decl::Origin, had: SetType, got: SetType) -> BuildError {
    BuildError {
        message: format!(
            "alias {name} at {origin}: already built as {had:?}, cannot also hold {got:?} \
             entries — an alias is either all ported or all unported"
        ),
    }
}

/// Build every set from the alias declarations and the resolved names.
pub fn build(decls: &[Decl], resolved: &Resolved) -> Result<Sets, BuildError> {
    let mut sets = Sets::default();

    for decl in decls {
        let Decl::Alias(Alias { name, host, port, proto, origin }) = decl else {
            continue;
        };

        let port_field = port.as_ref().map(|p| port_spec(p, proto.as_deref()));

        match classify(host) {
            Host::Any => {
                // `any` with a port is a port-only set; without one it would
                // match everything, which the shell has no representation for.
                let Some(spec) = &port_field else {
                    return Err(BuildError {
                        message: format!(
                            "alias {name} at {origin}: host 'any' needs a port"
                        ),
                    });
                };
                // A port bitmap has no family, but rules look it up per family,
                // so it is registered under both.
                for family in [Family::V4, Family::V6] {
                    let set = sets
                        .entry_for(name, family, SetType::Port)
                        .map_err(|had| mixed(name, origin, had, SetType::Port))?;
                    set.entries.push(spec.clone());
                }
            }
            Host::Literal(literal) => {
                let family = Family::of_literal(&literal);
                let set_type = if port_field.is_some() { SetType::NetPort } else { SetType::Net };
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
                    let set_type = if port_field.is_some() { SetType::NetPort } else { SetType::Net };
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
        let _ = writeln!(out, "create {name} {}", set.set_type.create_args(set.family));
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
        build(&parse(input).unwrap(), r).unwrap()
    }

    #[test]
    fn net_set_has_one_dimension_and_netport_has_two() {
        let input = rec(&["alias", "a.sh", "1", "plain", "10.0.0.0/8"])
            + &rec(&["alias", "a.sh", "2", "ported", "10.0.0.0/8", "53", "udp"]);
        let sets = build_from(&input, &resolved(&[]));
        assert_eq!(sets.get("plain", Family::V4).unwrap().set_type.dimensions(), 1);
        assert_eq!(sets.get("ported", Family::V4).unwrap().set_type.dimensions(), 2);
    }

    #[test]
    fn v6_literal_lands_in_the_v6_set() {
        let input = rec(&["alias", "a.sh", "1", "net", "10.10.255.32/28"])
            + &rec(&["alias", "a.sh", "2", "net", "fd51:2050:2220:502::/64"]);
        let sets = build_from(&input, &resolved(&[]));
        assert_eq!(sets.get("net", Family::V4).unwrap().entries, ["10.10.255.32/28"]);
        assert_eq!(sets.get("net", Family::V6).unwrap().entries, ["fd51:2050:2220:502::/64"]);
        assert_eq!(sets.get("net", Family::V6).unwrap().name, "net_v6");
    }

    #[test]
    fn a_name_fans_out_into_both_families() {
        let input = rec(&["alias", "a.sh", "1", "svc", "host.example.test", "53", "udp"]);
        let r = resolved(&[("host.example.test", &["192.0.2.1", "2001:db8::1"])]);
        let sets = build_from(&input, &r);
        assert_eq!(sets.get("svc", Family::V4).unwrap().entries, ["192.0.2.1,udp:53"]);
        assert_eq!(sets.get("svc", Family::V6).unwrap().entries, ["2001:db8::1,udp:53"]);
    }

    #[test]
    fn multiple_addresses_all_become_entries() {
        let input = rec(&["alias", "a.sh", "1", "pool", "pool.example.test"]);
        let r = resolved(&[("pool.example.test", &["192.0.2.1", "192.0.2.2", "192.0.2.3"])]);
        let sets = build_from(&input, &r);
        assert_eq!(sets.get("pool", Family::V4).unwrap().entries.len(), 3);
    }

    #[test]
    fn port_defaults_to_bare_when_no_proto() {
        let input = rec(&["alias", "a.sh", "1", "svc", "10.0.0.1", "8200"]);
        let sets = build_from(&input, &resolved(&[]));
        assert_eq!(sets.get("svc", Family::V4).unwrap().entries, ["10.0.0.1,8200"]);
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
    fn any_without_a_port_is_rejected() {
        let input = rec(&["alias", "a.sh", "1", "bad", "any"]);
        let e = build(&parse(&input).unwrap(), &resolved(&[])).unwrap_err();
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
        let e = build(&parse(&input).unwrap(), &resolved(&[])).unwrap_err();
        assert!(e.message.contains("all ported or all unported"), "{}", e.message);
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

        let sets = build(&decls, &Resolved { addrs }).expect("production config must build");
        let out = render(&sets, "CFWPROBE_");
        std::fs::write("scratch/ipset-restore-b2e9.txt", &out).unwrap();
        println!("{} sets, {} lines", sets.by_name.len(), out.lines().count());
    }
}

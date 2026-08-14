//! Name resolution for the whole config, in one pass before anything is built.
//!
//! Every unique name is resolved once, so a rotating pool cannot make two
//! aliases disagree, and a failure aborts while nothing has been submitted.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use hickory_resolver::net::NetError;
use hickory_resolver::{Resolver, TokioResolver};

use crate::decl::{Alias, Decl, Origin, Rule};

/// A host as written in the config, before resolution.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Host {
    /// Address or CIDR, used as written.
    Literal(String),
    /// The literal `any`.
    Any,
    /// Needs DNS.
    Name(String),
}

pub fn classify(host: &str) -> Host {
    if host.eq_ignore_ascii_case("any") {
        Host::Any
    } else if host.starts_with(|c: char| c.is_ascii_digit()) && !host.contains(char::is_alphabetic)
        || host.contains(':')
    {
        // Matches fw_alias_host: leading-digit dotted forms and anything with a
        // colon are addresses; everything else is resolved.
        Host::Literal(host.to_string())
    } else {
        Host::Name(host.to_string())
    }
}

/// Where a name was used, so a failure can name it.
#[derive(Debug, Clone)]
pub struct Usage {
    pub context: String,
    pub origin: Origin,
}

/// Collect every name needing DNS, with the places it is used.
pub fn names_to_resolve(decls: &[Decl]) -> BTreeMap<String, Vec<Usage>> {
    let mut names: BTreeMap<String, Vec<Usage>> = BTreeMap::new();

    let mut note = |host: &str, context: String, origin: &Origin| {
        if let Host::Name(n) = classify(host) {
            names.entry(n).or_default().push(Usage {
                context,
                origin: origin.clone(),
            });
        }
    };

    for d in decls {
        match d {
            Decl::Alias(Alias { name, host, origin, .. }) => {
                note(host, format!("alias {name}"), origin);
            }
            Decl::Rule(Rule { src, dst, origin, .. }) => {
                note(src, "rule source".to_string(), origin);
                note(dst, "rule destination".to_string(), origin);
            }
        }
    }

    names
}

pub struct Resolved {
    pub addrs: BTreeMap<String, Vec<IpAddr>>,
}

impl Resolved {
    pub fn get(&self, name: &str) -> &[IpAddr] {
        self.addrs.get(name).map_or(&[], Vec::as_slice)
    }
}

/// One name's outcome. A name with no addresses at all is a failure; having
/// only one family is normal and not an error.
async fn lookup(resolver: &TokioResolver, name: &str) -> Result<Vec<IpAddr>, NetError> {
    match resolver.lookup_ip(name).await {
        Ok(r) => Ok(r.iter().collect()),
        Err(e) if e.is_no_records_found() => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Resolve every name concurrently. Returns all failures rather than the first,
/// so one run reports every broken name instead of one per re-run.
pub async fn resolve_all(
    names: &BTreeMap<String, Vec<Usage>>,
) -> Result<Resolved, Vec<String>> {
    // Reads /etc/resolv.conf, so nameservers, timeout and attempts match dig's.
    let resolver = match Resolver::builder_tokio().and_then(|b| b.build()) {
        Ok(resolver) => resolver,
        Err(e) => return Err(vec![format!("reading resolver configuration: {e}")]),
    };

    let results = futures::future::join_all(
        names
            .keys()
            .map(|name| async { (name.clone(), lookup(&resolver, name).await) }),
    )
    .await;

    let mut addrs = BTreeMap::new();
    let mut failures = Vec::new();

    for (name, result) in results {
        let used_by = |names: &BTreeMap<String, Vec<Usage>>| {
            names
                .get(&name)
                .map(|u| {
                    u.iter()
                        .map(|u| format!("{} at {}", u.context, u.origin))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };

        match result {
            Ok(list) if list.is_empty() => {
                failures.push(format!("{name} resolved to no address ({})", used_by(names)));
            }
            Ok(list) => {
                addrs.insert(name, list);
            }
            Err(e) => {
                failures.push(format!("{name}: {e} ({})", used_by(names)));
            }
        }
    }

    if failures.is_empty() {
        Ok(Resolved { addrs })
    } else {
        Err(failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::parse;

    fn rec(fields: &[&str]) -> String {
        format!("{}\n", fields.join("\0"))
    }

    #[test]
    fn classifies_hosts_like_the_shell_does() {
        assert_eq!(classify("any"), Host::Any);
        assert_eq!(classify("ANY"), Host::Any);
        assert_eq!(classify("10.10.4.0/24"), Host::Literal("10.10.4.0/24".into()));
        assert_eq!(classify("24.226.190.130"), Host::Literal("24.226.190.130".into()));
        assert_eq!(
            classify("fd51:2050:2220:4::/64"),
            Host::Literal("fd51:2050:2220:4::/64".into())
        );
        assert_eq!(
            classify("casrvdns1.ad.cauca.ca"),
            Host::Name("casrvdns1.ad.cauca.ca".into())
        );
    }

    #[test]
    fn hostnames_starting_with_a_digit_are_names() {
        // 0.ntp.ad.cauca.ca appears in the production config.
        assert_eq!(
            classify("0.ntp.ad.cauca.ca"),
            Host::Name("0.ntp.ad.cauca.ca".into())
        );
    }

    #[test]
    fn collects_names_from_aliases_and_rule_endpoints() {
        let input = rec(&["alias", "a.sh", "1", "svc", "host.example.test", "53", "udp"])
            + &rec(&["alias", "a.sh", "2", "net", "10.0.0.0/8"])
            + &rec(&["rule", "a.sh", "3", "filter", "forward", "other.example.test", "any", "-j", "ACCEPT"]);
        let names = names_to_resolve(&parse(&input).unwrap());
        assert_eq!(names.len(), 2);
        assert!(names.contains_key("host.example.test"));
        assert!(names.contains_key("other.example.test"));
    }

    #[test]
    fn one_name_used_twice_is_resolved_once() {
        let input = rec(&["alias", "a.sh", "1", "one", "shared.example.test"])
            + &rec(&["alias", "a.sh", "2", "two", "shared.example.test"]);
        let names = names_to_resolve(&parse(&input).unwrap());
        assert_eq!(names.len(), 1);
        assert_eq!(names["shared.example.test"].len(), 2);
    }
}

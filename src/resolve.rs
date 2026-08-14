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
///
/// A rule endpoint naming an alias is not a hostname: the alias supplies the
/// set, and resolving its name would send the alias to DNS.
pub fn names_to_resolve(decls: &[Decl]) -> BTreeMap<String, Vec<Usage>> {
    let aliases: BTreeSet<&str> = decls
        .iter()
        .filter_map(|d| match d {
            Decl::Alias(Alias { name, .. }) => Some(name.as_str()),
            Decl::Rule(_) => None,
        })
        .collect();

    let mut names: BTreeMap<String, Vec<Usage>> = BTreeMap::new();

    for d in decls {
        // An alias's own host is resolved even where it shares a name with
        // another alias: that is the value being defined, not a reference.
        let uses: [(&str, String, &Origin); 2] = match d {
            Decl::Alias(Alias { name, host, origin, .. }) => [
                (host.as_str(), format!("alias {name}"), origin),
                ("", String::new(), origin),
            ],
            Decl::Rule(Rule { src, dst, origin, .. }) => [
                (src.as_str(), "rule source".to_string(), origin),
                (dst.as_str(), "rule destination".to_string(), origin),
            ],
        };
        let referenced = matches!(d, Decl::Rule(_));

        for (host, context, origin) in uses {
            if host.is_empty() || (referenced && aliases.contains(host)) {
                continue;
            }
            if let Host::Name(n) = classify(host) {
                names.entry(n).or_default().push(Usage {
                    context,
                    origin: origin.clone(),
                });
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
    // Keyed by where the name is used, so the report reads in the order the
    // config files do: cleaning up a run's worth of dead names is one pass
    // through the files rather than one reload per name.
    let mut failures: BTreeMap<(String, u32), Vec<String>> = BTreeMap::new();

    for (name, result) in results {
        let reason = match result {
            Ok(list) if !list.is_empty() => {
                addrs.insert(name, list);
                continue;
            }
            Ok(_) => "no address".to_string(),
            Err(e) => e.to_string(),
        };

        for usage in names.get(&name).map(Vec::as_slice).unwrap_or_default() {
            failures
                .entry((usage.origin.file.clone(), usage.origin.line))
                .or_default()
                .push(format!("{} ({}): {reason}", name, usage.context));
        }
    }

    if failures.is_empty() {
        return Ok(Resolved { addrs });
    }

    let mut report: Vec<String> = Vec::new();
    for ((file, line), mut entries) in failures {
        entries.sort();
        entries.dedup();
        for entry in entries {
            report.push(format!("{file}:{line}: {entry}"));
        }
    }
    Err(report)
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
    fn an_alias_used_as_an_endpoint_is_not_resolved() {
        let input = rec(&["alias", "a.sh", "1", "cc_dev", "10.0.0.0/8"])
            + &rec(&["rule", "10_x.sh", "2", "filter", "forward", "cc_dev", "any", "-j", "ACCEPT"]);
        let names = names_to_resolve(&parse(&input).unwrap());
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    fn an_alias_defined_only_by_dns_still_resolves_its_host() {
        let input = rec(&["alias", "a.sh", "1", "cadevk8s", "node1.example.test"])
            + &rec(&["rule", "10_x.sh", "2", "filter", "forward", "cadevk8s", "any", "-j", "ACCEPT"]);
        let names = names_to_resolve(&parse(&input).unwrap());
        assert_eq!(names.len(), 1);
        assert!(names.contains_key("node1.example.test"));
    }

    #[test]
    fn a_hostname_endpoint_that_is_not_an_alias_still_resolves() {
        let input = rec(&["alias", "a.sh", "1", "cc_dev", "10.0.0.0/8"])
            + &rec(&["rule", "10_x.sh", "2", "filter", "forward", "host.example.test", "cc_dev", "-j", "ACCEPT"]);
        let names = names_to_resolve(&parse(&input).unwrap());
        assert_eq!(names.len(), 1);
        assert!(names.contains_key("host.example.test"));
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

//! Rule construction and the `iptables-restore` stream.
//!
//! Rules are grouped by chain because a `:CHAIN` line flushes that chain even
//! under `--noflush`: a chain fed by several config files must be emitted once,
//! with all of its rules.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::decl::{Decl, Origin, Rule};
use crate::resolve::{classify, Host, Resolved};
use crate::sets::{Family, Sets};

/// Chain name as the shell spells it, without the CFWTMP_ prefix.
///
/// A global chain keeps its `+` and stands alone; a local one is qualified by
/// the config file it came from, so two files can use the same chain name.
fn chain_name(chain: &str, origin: &Origin) -> Result<String, BuildError> {
    if let Some(global) = chain.strip_prefix('+') {
        return Ok(format!("+{global}"));
    }

    // The shell matches NN_name.sh and drops the extension.
    let stem = origin
        .file
        .strip_suffix(".sh")
        .filter(|s| {
            s.split_once('_')
                .is_some_and(|(n, rest)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty())
        })
        .ok_or_else(|| BuildError {
            message: format!(
                "rule at {origin}: config file must be named NN_name.sh to qualify chain {chain:?}"
            ),
        })?;

    Ok(format!("{stem}+{chain}"))
}

#[derive(Debug)]
pub struct BuildError {
    pub message: String,
}

/// One emitted rule: the argument text after `-A CHAIN`.
#[derive(Debug, PartialEq, Eq)]
pub struct Emitted {
    pub chain: String,
    pub args: String,
}

/// Rules for one family, grouped by table then chain, in declaration order.
#[derive(Debug, Default)]
pub struct Table {
    pub chains: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default)]
pub struct Ruleset {
    pub tables: BTreeMap<String, Table>,
}

/// Quote an argument for iptables-restore, which splits on whitespace and
/// honours double quotes.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '"', '\t']) {
        return arg.to_string();
    }
    format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Render one endpoint as match arguments, or None if this rule cannot exist
/// for this family — an alias with no set on this side.
fn endpoint(
    address: &str,
    direction: &str,
    family: Family,
    sets: &Sets,
    prefix: &str,
) -> Option<Option<String>> {
    match classify(address) {
        Host::Any => Some(None),
        Host::Literal(literal) => {
            // A literal belongs to one family; on the other it cannot match.
            if Family::of_literal(&literal) != family {
                return None;
            }
            let flag = if direction == "src" { "-s" } else { "-d" };
            Some(Some(format!("{flag} {literal}")))
        }
        Host::Name(name) => {
            // A hostname in a rule is resolved and expanded by the caller; by
            // the time it reaches here it is either an alias or a literal.
            let set = sets.get(&name, family)?;
            let dirs = vec![direction; set.set_type.dimensions()].join(",");
            Some(Some(format!(
                "-m set --match-set {prefix}{} {dirs}",
                set.name
            )))
        }
    }
}

/// The tail as offered to the probe. A jump to a generated chain names one that
/// does not exist yet, which every family would reject, so it becomes a target
/// both families accept — the question being asked is about the match options.
fn probe_tail(tail: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tail.len());
    let mut expect_target = false;

    for arg in tail {
        if expect_target && arg.starts_with('+') {
            out.push("ACCEPT".to_string());
        } else {
            out.push(arg.clone());
        }
        expect_target = arg == "-j";
    }

    out
}

/// Rewrite `-j +chain` so the target names the temporary chain.
fn rewrite_targets(tail: &[String], prefix: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tail.len());
    let mut expect_target = false;

    for arg in tail {
        if expect_target && arg.starts_with('+') {
            out.push(format!("{prefix}{arg}"));
        } else {
            out.push(arg.clone());
        }
        expect_target = arg == "-j";
    }

    out
}

/// Build both families' rulesets. `prefix` is the CFWTMP_ chain/set prefix.
pub fn build(
    decls: &[Decl],
    sets: &Sets,
    resolved: &Resolved,
    prefix: &str,
    families_for: &mut dyn FnMut(&[String]) -> Vec<Family>,
) -> Result<BTreeMap<Family, Ruleset>, BuildError> {
    let mut out: BTreeMap<Family, Ruleset> = BTreeMap::new();

    for decl in decls {
        let Decl::Rule(Rule { table, chain, src, dst, tail, origin }) = decl else {
            continue;
        };

        let chain = chain_name(chain, origin)?;
        let families = families_for(&probe_tail(tail));
        let tail = rewrite_targets(tail, prefix);

        for family in families {
            // A hostname endpoint expands to one rule per address of this
            // family; anything else yields a single rule.
            let src_variants = expand(src, family, resolved);
            let dst_variants = expand(dst, family, resolved);

            for src_one in &src_variants {
                for dst_one in &dst_variants {
                    let Some(src_args) = endpoint(src_one, "src", family, sets, prefix) else {
                        continue;
                    };
                    let Some(dst_args) = endpoint(dst_one, "dst", family, sets, prefix) else {
                        continue;
                    };

                    let mut args = String::new();
                    for part in [src_args, dst_args].into_iter().flatten() {
                        args.push_str(&part);
                        args.push(' ');
                    }
                    for arg in &tail {
                        args.push_str(&quote(arg));
                        args.push(' ');
                    }

                    out.entry(family)
                        .or_default()
                        .tables
                        .entry(table.clone())
                        .or_default()
                        .chains
                        .entry(chain.clone())
                        .or_default()
                        .push(args.trim_end().to_string());
                }
            }
        }
    }

    Ok(out)
}

/// A hostname endpoint becomes one literal per resolved address of this family.
/// Everything else passes through unchanged.
fn expand(address: &str, family: Family, resolved: &Resolved) -> Vec<String> {
    match classify(address) {
        Host::Name(name) => {
            let addrs: Vec<String> = resolved
                .get(&name)
                .iter()
                .filter(|a| Family::of(a) == family)
                .map(|a| a.to_string())
                .collect();
            // Not a resolved name: it is an alias, and passes through so the
            // set lookup can happen.
            if addrs.is_empty() && resolved.get(&name).is_empty() {
                vec![address.to_string()]
            } else {
                addrs
            }
        }
        _ => vec![address.to_string()],
    }
}

/// Render one family's `iptables-restore` stream.
pub fn render(ruleset: &Ruleset, prefix: &str) -> String {
    let mut out = String::new();

    for (table, t) in &ruleset.tables {
        let _ = writeln!(out, "*{table}");
        for chain in t.chains.keys() {
            let _ = writeln!(out, ":{prefix}{chain} - [0:0]");
        }
        for (chain, rules) in &t.chains {
            for rule in rules {
                let _ = writeln!(out, "-A {prefix}{chain} {rule}");
            }
        }
        let _ = writeln!(out, "COMMIT");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::parse;
    use crate::sets;
    use std::collections::BTreeMap;

    fn rec(fields: &[&str]) -> String {
        format!("{}\n", fields.join("\0"))
    }

    fn resolved(pairs: &[(&str, &[&str])]) -> Resolved {
        let mut addrs = BTreeMap::new();
        for (name, list) in pairs {
            addrs.insert(name.to_string(), list.iter().map(|a| a.parse().unwrap()).collect());
        }
        Resolved { addrs }
    }

    /// Both families accept everything, as when probing is unavailable.
    fn both(_: &[String]) -> Vec<Family> {
        vec![Family::V4, Family::V6]
    }

    fn build_all(input: &str, r: &Resolved) -> BTreeMap<Family, Ruleset> {
        let decls = parse(input).unwrap();
        let s = sets::build(&decls, r).unwrap();
        build(&decls, &s, r, "CFWTMP_", &mut both).unwrap()
    }

    #[test]
    fn global_chain_keeps_its_plus() {
        let input = rec(&["rule", "12_drops.sh", "5", "filter", "+reject", "any", "any", "-j", "REJECT"]);
        let out = build_all(&input, &resolved(&[]));
        assert!(out[&Family::V4].tables["filter"].chains.contains_key("+reject"));
    }

    #[test]
    fn local_chain_is_qualified_by_its_file() {
        let input = rec(&["rule", "30_cadev.sh", "1", "filter", "forward", "any", "any", "-j", "ACCEPT"]);
        let out = build_all(&input, &resolved(&[]));
        assert!(out[&Family::V4].tables["filter"].chains.contains_key("30_cadev+forward"));
    }

    #[test]
    fn a_chain_fed_by_two_files_is_emitted_once() {
        let input = rec(&["rule", "12_drops.sh", "5", "filter", "+reject", "any", "any", "-j", "REJECT"])
            + &rec(&["rule", "50_log.sh", "2", "filter", "+reject", "any", "any", "-j", "DROP"]);
        let out = build_all(&input, &resolved(&[]));
        let text = render(&out[&Family::V4], "CFWTMP_");
        assert_eq!(text.matches(":CFWTMP_+reject").count(), 1);
        assert_eq!(text.matches("-A CFWTMP_+reject").count(), 2);
    }

    #[test]
    fn jump_to_a_global_chain_is_prefixed() {
        let input = rec(&["rule", "12_drops.sh", "15", "filter", "+log_reject", "any", "any", "-j", "+reject"]);
        let out = build_all(&input, &resolved(&[]));
        let text = render(&out[&Family::V4], "CFWTMP_");
        assert!(text.contains("-j CFWTMP_+reject"), "{text}");
    }

    #[test]
    fn alias_endpoint_emits_matching_direction_count() {
        let input = rec(&["alias", "a.sh", "1", "plain", "10.0.0.0/8"])
            + &rec(&["alias", "a.sh", "2", "ported", "10.0.0.0/8", "53", "udp"])
            + &rec(&["rule", "10_x.sh", "3", "filter", "forward", "plain", "ported", "-j", "ACCEPT"]);
        let out = build_all(&input, &resolved(&[]));
        let text = render(&out[&Family::V4], "CFWTMP_");
        assert!(text.contains("--match-set CFWTMP_plain src "), "{text}");
        assert!(text.contains("--match-set CFWTMP_ported dst,dst "), "{text}");
    }

    #[test]
    fn a_rule_is_skipped_where_its_alias_has_no_set() {
        let input = rec(&["alias", "a.sh", "1", "v4only", "10.0.0.0/8"])
            + &rec(&["rule", "10_x.sh", "2", "filter", "forward", "v4only", "any", "-j", "ACCEPT"]);
        let out = build_all(&input, &resolved(&[]));
        assert!(out.contains_key(&Family::V4));
        assert!(!out.contains_key(&Family::V6));
    }

    #[test]
    fn literal_endpoint_goes_to_its_own_family_only() {
        let input = rec(&["rule", "10_x.sh", "1", "filter", "forward", "10.0.0.1", "any", "-j", "ACCEPT"]);
        let out = build_all(&input, &resolved(&[]));
        assert!(out[&Family::V4].tables["filter"].chains["10_x+forward"][0].starts_with("-s 10.0.0.1"));
        assert!(!out.contains_key(&Family::V6));
    }

    #[test]
    fn hostname_endpoint_expands_to_one_rule_per_address() {
        let input = rec(&["rule", "10_x.sh", "1", "filter", "forward", "pool.example.test", "any", "-j", "ACCEPT"]);
        let r = resolved(&[("pool.example.test", &["192.0.2.1", "192.0.2.2", "2001:db8::1"])]);
        let out = build_all(&input, &r);
        assert_eq!(out[&Family::V4].tables["filter"].chains["10_x+forward"].len(), 2);
        assert_eq!(out[&Family::V6].tables["filter"].chains["10_x+forward"].len(), 1);
    }

    #[test]
    fn any_endpoint_emits_no_match() {
        let input = rec(&["rule", "10_x.sh", "1", "filter", "forward", "any", "any", "-j", "ACCEPT"]);
        let out = build_all(&input, &resolved(&[]));
        assert_eq!(out[&Family::V4].tables["filter"].chains["10_x+forward"][0], "-j ACCEPT");
    }

    #[test]
    fn tail_arguments_with_spaces_are_quoted() {
        let input = rec(&[
            "rule", "12_drops.sh", "10", "filter", "+log_drop", "any", "any",
            "-j", "LOG", "--log-prefix", "LD: ",
        ]);
        let out = build_all(&input, &resolved(&[]));
        let text = render(&out[&Family::V4], "CFWTMP_");
        assert!(text.contains(r#"--log-prefix "LD: ""#), "{text}");
    }

    #[test]
    fn each_table_gets_its_own_commit() {
        let input = rec(&["rule", "10_x.sh", "1", "filter", "forward", "any", "any", "-j", "ACCEPT"])
            + &rec(&["rule", "10_x.sh", "2", "nat", "prerouting", "any", "any", "-j", "REDIRECT"]);
        let out = build_all(&input, &resolved(&[]));
        let text = render(&out[&Family::V4], "CFWTMP_");
        assert_eq!(text.matches("COMMIT").count(), 2);
        assert!(text.contains("*filter"));
        assert!(text.contains("*nat"));
    }

    #[test]
    fn rule_order_within_a_chain_is_preserved() {
        let input = rec(&["rule", "12_drops.sh", "5", "filter", "+reject", "any", "any", "-p", "tcp", "-j", "REJECT"])
            + &rec(&["rule", "12_drops.sh", "6", "filter", "+reject", "any", "any", "-j", "REJECT"])
            + &rec(&["rule", "12_drops.sh", "7", "filter", "+reject", "any", "any", "-j", "DROP"]);
        let out = build_all(&input, &resolved(&[]));
        let rules = &out[&Family::V4].tables["filter"].chains["+reject"];
        assert_eq!(rules[0], "-p tcp -j REJECT");
        assert_eq!(rules[2], "-j DROP");
    }

    #[test]
    fn a_tail_only_one_family_accepts_is_emitted_once() {
        let input = rec(&["rule", "50_log.sh", "9", "filter", "forward", "any", "any",
                          "-p", "icmpv6", "--icmpv6-type", "echo-request", "-j", "DROP"]);
        let decls = parse(&input).unwrap();
        let s = sets::build(&decls, &resolved(&[])).unwrap();
        let out = build(&decls, &s, &resolved(&[]), "CFWTMP_", &mut |_| vec![Family::V6]).unwrap();
        assert!(!out.contains_key(&Family::V4));
        assert_eq!(out[&Family::V6].tables["filter"].chains["50_log+forward"].len(), 1);
    }

    #[test]
    fn probe_sees_a_concrete_target_not_a_generated_chain() {
        let tail: Vec<String> = ["-j", "+reject"].iter().map(|s| s.to_string()).collect();
        assert_eq!(probe_tail(&tail), vec!["-j".to_string(), "ACCEPT".to_string()]);
    }

    #[test]
    fn badly_named_config_file_is_rejected() {
        let input = rec(&["rule", "notnumbered.sh", "1", "filter", "forward", "any", "any", "-j", "ACCEPT"]);
        let decls = parse(&input).unwrap();
        let s = sets::build(&decls, &resolved(&[])).unwrap();
        let e = build(&decls, &s, &resolved(&[]), "CFWTMP_", &mut both).unwrap_err();
        assert!(e.message.contains("NN_name.sh"), "{}", e.message);
    }
}

#[cfg(test)]
mod production_fixture {
    use super::*;
    use crate::decl::parse;
    use crate::resolve::{names_to_resolve, Resolved};
    use crate::sets;
    use std::collections::BTreeMap;

    #[test]
    #[ignore]
    fn render_production_rules() {
        let input = std::fs::read_to_string("scratch/decls-b2e9.txt").expect("fixture missing");
        let decls = parse(&input).unwrap();

        let mut addrs = BTreeMap::new();
        for name in names_to_resolve(&decls).keys() {
            addrs.insert(
                name.clone(),
                vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            );
        }
        let r = Resolved { addrs };

        let s = sets::build(&decls, &r).unwrap();
        let out = build(&decls, &s, &r, "CFWPRB_", &mut |_: &[String]| vec![Family::V4, Family::V6])
            .expect("production rules must build");

        for (family, ruleset) in &out {
            let name = match family {
                Family::V4 => "v4",
                Family::V6 => "v6",
            };
            let text = render(ruleset, "CFWPRB_");
            let chains: usize = ruleset.tables.values().map(|t| t.chains.len()).sum();
            let count: usize = ruleset.tables.values().flat_map(|t| t.chains.values()).map(Vec::len).sum();
            println!("{name}: {chains} chains, {count} rules, {} lines", text.lines().count());
            std::fs::write(format!("scratch/iptables-restore-{name}-b2e9.txt"), text).unwrap();
        }
    }
}

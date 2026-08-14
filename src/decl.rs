//! Declarations streamed from the shell on fd 3.
//!
//! Records are NUL-delimited fields terminated by a newline. Bash has already
//! word-split each declaration, so fields are passed through as argv and never
//! re-parsed here — tails contain spaces, quotes and `#`.

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Decl {
    Alias(Alias),
    Rule(Rule),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Alias {
    pub name: String,
    /// Hostname, address, CIDR, or the literal `any`.
    pub host: String,
    pub port: Option<String>,
    pub proto: Option<String>,
    pub origin: Origin,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    pub table: String,
    /// Chain as written, `+` prefix retained: it selects a global chain.
    pub chain: String,
    pub src: String,
    pub dst: String,
    /// Everything after src/dst, one element per shell word.
    pub tail: Vec<String>,
    pub origin: Origin,
}

/// Where a declaration came from, for diagnostics and for deriving chain names.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Origin {
    pub file: String,
    pub line: u32,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

#[derive(Debug)]
pub struct ParseError {
    pub record: u64,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "record {}: {}", self.record, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parse one NUL-delimited record.
///
/// Layout: KIND, file, line, then the verb's own fields.
fn parse_record(fields: &[&str], record: u64) -> Result<Decl, ParseError> {
    let err = |m: String| ParseError { record, message: m };

    let (kind, file, line, rest) = match fields {
        [kind, file, line, rest @ ..] => (*kind, *file, *line, rest),
        _ => {
            return Err(err(format!(
                "expected at least 3 fields, got {}",
                fields.len()
            )))
        }
    };

    let line: u32 = line
        .parse()
        .map_err(|_| err(format!("line number is not a number: {line:?}")))?;
    let origin = Origin {
        file: file.to_string(),
        line,
    };

    match kind {
        "alias" => {
            let (name, host, opt) = match rest {
                [name, host, opt @ ..] => (*name, *host, opt),
                _ => return Err(err("alias needs NAME and HOST".into())),
            };
            if name.is_empty() {
                return Err(err("alias name is empty".into()));
            }
            // A dot or colon in the name would be read as a literal address
            // wherever the alias is used in a rule.
            if name.contains(['.', ':']) {
                return Err(err(format!("alias name {name:?} contains '.' or ':'")));
            }
            if host.is_empty() {
                return Err(err(format!("alias {name}: host is empty")));
            }
            let mut opt = opt.iter().filter(|f| !f.is_empty());
            Ok(Decl::Alias(Alias {
                name: name.to_string(),
                host: host.to_string(),
                port: opt.next().map(|s| s.to_string()),
                proto: opt.next().map(|s| s.to_lowercase()),
                origin,
            }))
        }
        "rule" => {
            let (table, chain, src, dst, tail) = match rest {
                [table, chain, src, dst, tail @ ..] => (*table, *chain, *src, *dst, tail),
                _ => return Err(err("rule needs TABLE CHAIN SOURCE DESTINATION".into())),
            };
            for (label, v) in [
                ("table", table),
                ("chain", chain),
                ("source", src),
                ("destination", dst),
            ] {
                if v.is_empty() {
                    return Err(err(format!("rule {label} is empty")));
                }
            }
            Ok(Decl::Rule(Rule {
                table: table.to_string(),
                chain: chain.to_lowercase(),
                src: src.to_string(),
                dst: dst.to_string(),
                tail: tail.iter().map(|s| s.to_string()).collect(),
                origin,
            }))
        }
        other => Err(err(format!("unknown declaration kind {other:?}"))),
    }
}

/// Parse a whole stream. Records are newline-terminated, fields NUL-separated.
pub fn parse(input: &str) -> Result<Vec<Decl>, ParseError> {
    input
        .split('\n')
        .filter(|l| !l.is_empty())
        .enumerate()
        .map(|(i, line)| {
            let fields: Vec<&str> = line.split('\0').collect();
            parse_record(&fields, i as u64 + 1)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(fields: &[&str]) -> String {
        format!("{}\n", fields.join("\0"))
    }

    #[test]
    fn alias_with_port_and_proto() {
        let input = rec(&[
            "alias",
            "15_cauca.sh",
            "5",
            "cc_services",
            "casrvdns1.ad.cauca.ca",
            "53",
            "UDP",
        ]);
        let Decl::Alias(a) = &parse(&input).unwrap()[0] else {
            panic!("expected alias")
        };
        assert_eq!(a.name, "cc_services");
        assert_eq!(a.host, "casrvdns1.ad.cauca.ca");
        assert_eq!(a.port.as_deref(), Some("53"));
        assert_eq!(a.proto.as_deref(), Some("udp"));
        assert_eq!(a.origin.to_string(), "15_cauca.sh:5");
    }

    #[test]
    fn alias_without_port() {
        let input = rec(&[
            "alias",
            "15_cauca.sh",
            "51",
            "cc_ping",
            "casrvvrrpa.ad.cauca.ca",
        ]);
        let Decl::Alias(a) = &parse(&input).unwrap()[0] else {
            panic!("expected alias")
        };
        assert_eq!(a.port, None);
        assert_eq!(a.proto, None);
    }

    #[test]
    fn alias_takes_v4_and_v6_under_one_name() {
        let input = rec(&["alias", "15_cauca.sh", "56", "cc_omd", "10.10.255.32/28"])
            + &rec(&[
                "alias",
                "15_cauca.sh",
                "57",
                "cc_omd",
                "fd51:2050:2220:502::/64",
            ]);
        let decls = parse(&input).unwrap();
        assert_eq!(decls.len(), 2);
    }

    #[test]
    fn alias_name_with_dot_is_rejected() {
        let input = rec(&["alias", "f.sh", "1", "bad.name", "10.0.0.1"]);
        assert!(parse(&input).unwrap_err().message.contains("contains"));
    }

    #[test]
    fn rule_tail_keeps_spaces_and_quotes() {
        let input = rec(&[
            "rule",
            "12_drops.sh",
            "10",
            "filter",
            "+log_drop",
            "any",
            "any",
            "-m",
            "limit",
            "--limit",
            "1/sec",
            "-j",
            "LOG",
            "--log-prefix",
            "LD: ",
        ]);
        let Decl::Rule(r) = &parse(&input).unwrap()[0] else {
            panic!("expected rule")
        };
        assert_eq!(r.chain, "+log_drop");
        assert_eq!(r.tail.last().unwrap(), "LD: ");
    }

    #[test]
    fn rule_tail_keeps_hash_and_service_names() {
        let input = rec(&[
            "rule",
            "30_cadev.sh",
            "116",
            "filter",
            "forward",
            "cc_dev_srv",
            "any",
            "-p",
            "tcp",
            "--syn",
            "--dport",
            "whois",
            "-m",
            "comment",
            "--comment",
            "a # b",
        ]);
        let Decl::Rule(r) = &parse(&input).unwrap()[0] else {
            panic!("expected rule")
        };
        assert_eq!(r.tail[4], "whois");
        assert_eq!(r.tail.last().unwrap(), "a # b");
    }

    #[test]
    fn chain_is_lowercased_but_plus_kept() {
        let input = rec(&[
            "rule", "f.sh", "1", "filter", "FORWARD", "any", "any", "-j", "ACCEPT",
        ]);
        let Decl::Rule(r) = &parse(&input).unwrap()[0] else {
            panic!("expected rule")
        };
        assert_eq!(r.chain, "forward");
    }

    #[test]
    fn rule_with_empty_tail_parses() {
        let input = rec(&["rule", "f.sh", "1", "filter", "forward", "any", "any"]);
        let Decl::Rule(r) = &parse(&input).unwrap()[0] else {
            panic!("expected rule")
        };
        assert!(r.tail.is_empty());
    }

    #[test]
    fn missing_fields_report_the_record() {
        let input = rec(&["rule", "f.sh", "1", "filter"]);
        let e = parse(&input).unwrap_err();
        assert_eq!(e.record, 1);
        assert!(e.message.contains("TABLE CHAIN"));
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let input = rec(&["frobnicate", "f.sh", "1"]);
        assert!(parse(&input).unwrap_err().message.contains("unknown"));
    }
}

#[cfg(test)]
mod production_fixture {
    use super::*;

    /// The real config emitted by fw_declare.sh, captured from cadevrtr1.
    /// Ignored by default: the fixture is not in the repo.
    #[test]
    #[ignore]
    fn parses_production_stream() {
        let path = "scratch/decls-b2e9.txt";
        let input = std::fs::read_to_string(path).expect("fixture missing");
        let decls = parse(&input).expect("production stream must parse");
        let aliases = decls.iter().filter(|d| matches!(d, Decl::Alias(_))).count();
        let rules = decls.len() - aliases;
        println!("parsed {aliases} aliases, {rules} rules");
        assert_eq!(aliases, 211);
        assert_eq!(rules, 135);
    }
}

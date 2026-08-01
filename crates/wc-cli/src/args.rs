//! A small hand-rolled argument parser.
//!
//! No `clap`: the dependency budget (§8.2) says a new dependency needs
//! justifying, and Warden core parses its own flags too. Keeping the same style
//! matters more than saving fifty lines, because operators read one convention
//! across both tools.

use std::collections::BTreeMap;

/// Parsed command line: a verb path plus flags.
#[derive(Debug, Default)]
pub struct Args {
    /// Sub-command words, in order, e.g. `["register", "server"]`.
    pub verbs: Vec<String>,
    /// `--key value` and repeated `--key` pairs.
    pub flags: BTreeMap<String, Vec<String>>,
    /// Positional arguments after the verbs.
    pub positional: Vec<String>,
}

impl Args {
    /// Parse `std::env::args`-style input (without the program name).
    ///
    /// A word is a verb while it is not flag-like and no flag has been seen yet;
    /// after the first flag, bare words are positional. `--flag=value` and
    /// `--flag value` are both accepted; a flag with no value is `true`.
    #[must_use]
    pub fn parse<I: IntoIterator<Item = String>>(input: I) -> Args {
        let mut out = Args::default();
        let mut iter = input.into_iter().peekable();
        let mut seen_flag = false;

        while let Some(token) = iter.next() {
            if let Some(rest) = token.strip_prefix("--") {
                seen_flag = true;
                let (key, inline) = match rest.split_once('=') {
                    Some((k, v)) => (k.to_string(), Some(v.to_string())),
                    None => (rest.to_string(), None),
                };
                let value = match inline {
                    Some(v) => v,
                    None => {
                        // A following token is this flag's value unless it is
                        // itself a flag.
                        if iter.peek().is_some_and(|n| !n.starts_with("--")) {
                            iter.next().unwrap_or_default()
                        } else {
                            "true".to_string()
                        }
                    }
                };
                out.flags.entry(key).or_default().push(value);
            } else if seen_flag {
                out.positional.push(token);
            } else {
                out.verbs.push(token);
            }
        }
        out
    }

    /// The first `n` verb words joined with spaces.
    ///
    /// Callers match on a bounded prefix rather than the whole path, because a
    /// trailing positional id lands in `verbs` when it precedes any flag —
    /// `connect activate <id>` would otherwise read as a two-word command.
    #[must_use]
    pub fn verb_prefix(&self, n: usize) -> String {
        self.verbs
            .iter()
            .take(n)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// First value of a flag.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.flags
            .get(key)
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// Every value of a repeated flag, plus comma-split values, so
    /// `--approver a --approver b` and `--approver a,b` both work.
    #[must_use]
    pub fn list(&self, key: &str) -> Vec<String> {
        self.flags
            .get(key)
            .map(|values| {
                values
                    .iter()
                    .flat_map(|v| v.split(','))
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether a boolean flag is present and not explicitly `false`.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        match self.get(key) {
            Some(v) => v != "false",
            None => false,
        }
    }

    /// A flag's value parsed as a number.
    #[must_use]
    pub fn number(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.parse().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Args {
        Args::parse(line.split_whitespace().map(str::to_string))
    }

    #[test]
    fn verbs_come_before_flags() {
        let a = args("register server --endpoint https://x --tier 2");
        assert_eq!(a.verb_prefix(2), "register server");
        assert_eq!(a.get("endpoint"), Some("https://x"));
        assert_eq!(a.number("tier"), Some(2));
    }

    #[test]
    fn inline_and_separated_values_both_work() {
        let a = args("show --id=spiffe://x --owner human:a@b");
        assert_eq!(a.get("id"), Some("spiffe://x"));
        assert_eq!(a.get("owner"), Some("human:a@b"));
    }

    #[test]
    fn a_valueless_flag_is_true() {
        let a = args("posture --json --unattested");
        assert!(a.has("json"));
        assert!(a.has("unattested"));
        assert!(!a.has("drift"));
    }

    #[test]
    fn repeated_and_comma_lists_merge() {
        let a = args("quarantine --approver human:a --approver human:b,human:c");
        assert_eq!(
            a.list("approver"),
            vec![
                "human:a".to_string(),
                "human:b".to_string(),
                "human:c".to_string()
            ]
        );
    }

    #[test]
    fn positionals_follow_flags() {
        let a = args("audit verify --root /tmp/x extra");
        assert_eq!(a.verb_prefix(2), "audit verify");
        assert_eq!(a.positional, vec!["extra".to_string()]);
    }

    #[test]
    fn a_flag_before_another_flag_is_boolean() {
        let a = args("canon --json --kind mcp");
        assert!(a.has("json"));
        assert_eq!(a.get("kind"), Some("mcp"));
    }

    #[test]
    fn a_trailing_id_does_not_become_part_of_the_command() {
        // The bug this exists to prevent: `activate <id>` read as a two-word
        // command, so dispatch never matched.
        let a = args("activate urn:wc:abc123");
        assert_eq!(a.verb_prefix(1), "activate");
        assert_eq!(a.verbs.get(1).map(String::as_str), Some("urn:wc:abc123"));
    }

    #[test]
    fn an_empty_line_parses_to_nothing() {
        let a = args("");
        assert!(a.verbs.is_empty());
        assert!(a.flags.is_empty());
    }
}

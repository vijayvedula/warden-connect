//! The configuration file layer (`docs/08-lld.md` §8.13, production-readiness P1 #12).
//!
//! §8.13 says configuration resolves **flag over file over env**. Two of those three
//! existed: flags, and four hand-wired `WARDEN_CONNECT_*` lookups. There was no file
//! layer at all, so a deployment with thirty flags carried them in a unit file or a pod
//! spec, and `connect serve --config connect.toml` — which §8.13 shows in an example —
//! was not a thing the binary could do.
//!
//! # Unknown keys are errors
//!
//! The decision that makes this worth building rather than cosmetic. A config file whose
//! keys are silently ignored is the worst artifact in this repository's recurring bug
//! class: it reads as configured, it is version-controlled, it is reviewed by somebody
//! who believes it took effect, and nothing anywhere disagrees. `require_provenance =
//! true` in a section nobody reads is not a stricter deployment, it is a false belief
//! with an audit trail.
//!
//! So every key is either **mapped to a flag**, or **explicitly owned by another
//! loader**, or an **error naming what was expected**. There is no fourth case.
//!
//! # Sections owned elsewhere
//!
//! `[[sink]]` and `[assurance]` are read by `wc_control::sink::load_specs` and
//! `assurance::Config` directly from the same file, because they are structured data
//! rather than flag defaults — a sink list is not a command-line concept. They are
//! declared here as owned so that "this key does nothing" and "this key is handled by
//! somebody else" are different answers.
//!
//! # What is deliberately not mapped
//!
//! Several §8.13 keys describe behaviour this build does not have — `[server].tls`
//! (TLS is terminated in front, by design), `[policy].hot_reload` and `pdp_url`,
//! `[admission].rekor`. Mapping them to nothing would be exactly the failure above, so
//! they are listed as **unimplemented** and refused with the reason. An operator who
//! writes `hot_reload = true` is told it does not exist, rather than discovering later
//! that a SIGHUP did nothing.

use std::collections::BTreeMap;

use wc_core::error::{Code, Result, WcError};

use crate::args::Args;

/// A `connect.toml` key and the flag it stands in for.
struct Mapping {
    /// `section.key` as written in the file. An empty section means a top-level key.
    path: &'static str,
    /// The long flag this fills in, without `--`.
    flag: &'static str,
}

/// Every file key that resolves to a flag.
///
/// Kept as data rather than a `match` so `every_mapped_flag_is_a_real_flag` can walk it
/// and assert the other side exists — a mapping to a flag no command accepts would be a
/// key that parses, validates, and does nothing.
const MAPPINGS: &[Mapping] = &[
    // [server]
    Mapping {
        path: "server.listen",
        flag: "listen",
    },
    Mapping {
        path: "server.tenant",
        flag: "tenant",
    },
    Mapping {
        path: "server.root",
        flag: "root",
    },
    Mapping {
        path: "server.behind_tls_proxy",
        flag: "behind-tls-proxy",
    },
    Mapping {
        path: "server.trusted_proxy",
        flag: "trusted-proxy",
    },
    Mapping {
        path: "server.insecure_plaintext",
        flag: "insecure-plaintext",
    },
    // [policy]
    Mapping {
        path: "policy.path",
        flag: "policy",
    },
    // [identity]
    Mapping {
        path: "identity.jwks",
        flag: "jwks",
    },
    Mapping {
        path: "identity.aud",
        flag: "aud",
    },
    Mapping {
        path: "identity.approvers",
        flag: "approvers",
    },
    // [keys]
    Mapping {
        path: "keys.keyring",
        flag: "keyring",
    },
    Mapping {
        path: "keys.kid",
        flag: "kid",
    },
    Mapping {
        path: "keys.issuer",
        flag: "issuer-key",
    },
    Mapping {
        path: "keys.issuer_signer",
        flag: "signer",
    },
    Mapping {
        path: "keys.revocation",
        flag: "revocation-key",
    },
    Mapping {
        path: "keys.revocation_signer",
        flag: "revocation-signer",
    },
    Mapping {
        path: "keys.revocation_kid",
        flag: "revocation-kid",
    },
    Mapping {
        path: "keys.break_glass_kid",
        flag: "break-glass-kid",
    },
    Mapping {
        path: "keys.anchor",
        flag: "anchor-key",
    },
    Mapping {
        path: "keys.anchor_signer",
        flag: "anchor-signer",
    },
    Mapping {
        path: "keys.require_external_signing",
        flag: "require-external-signing",
    },
    // [screen]
    Mapping {
        path: "screen.mode",
        flag: "screen-mode",
    },
    Mapping {
        path: "screen.rules",
        flag: "screen-rules",
    },
    // [evidence]
    Mapping {
        path: "evidence.anchor_interval",
        flag: "anchor-interval",
    },
    // [tokens]
    Mapping {
        path: "tokens.path",
        flag: "tokens",
    },
];

/// Every flag the mapping table can fill, for the test that asserts they are real flags.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use]
pub fn mapped_flags() -> Vec<&'static str> {
    MAPPINGS.iter().map(|m| m.flag).collect()
}

/// Sections another loader reads from this same file. Present, valid, not ours.
const OWNED_ELSEWHERE: &[&str] = &["sink", "assurance", "breakglass", "retention"];

/// §8.13 keys this build does not implement, with the reason an operator needs.
///
/// Refused rather than ignored: see the module note. Each entry is the honest answer to
/// "I set this and nothing changed".
const UNIMPLEMENTED: &[(&str, &str)] = &[
    (
        "server.mode",
        "there is no control-plane-wide observe mode; observe is a mediator flag \
         (`connect-mediate --observe`) because it governs enforcement, which happens there",
    ),
    (
        "server.tls",
        "TLS is terminated in front of this process in every supported topology \
         (docs/physical-architecture.md); use server.behind_tls_proxy and \
         server.trusted_proxy instead",
    ),
    (
        "policy.hot_reload",
        "not implemented; the policy is read at startup and a change needs a restart. \
         Setting this would suggest SIGHUP reloads it, and nothing does",
    ),
    (
        "policy.pdp_url",
        "AuthZEN passthrough is not implemented (P2 #16); a URL here would be ignored \
         on every decision",
    ),
    (
        "identity.mode",
        "peer identity mode is a mediator concern; use `connect-mediate --peer-mode`",
    ),
    (
        "identity.trust_bundle",
        "not implemented as a file-level default; pass --trust-key KID=PEM per key, or \
         --jwks for a key set",
    ),
    (
        "admission.require_provenance",
        "not implemented as a default; provenance is required per registration by \
         supplying --attest, and its absence leaves stage 4 skipped rather than passed",
    ),
    (
        "admission.require_card_signature",
        "not implemented as a default; pass --require-card-signature per registration",
    ),
    (
        "admission.rekor",
        "transparency-log lookup is not implemented; provenance is verified against \
         --prov-key, not against Rekor",
    ),
    (
        "evidence.chain",
        "the chain path is derived from --root and the tenant, so that one root holds one \
         estate; overriding it would let two tenants share a chain",
    ),
];

/// Flag defaults read from a file.
///
/// The file path is not held: every error raised while reading it already names it, and
/// a second copy would be a second thing to keep in step.
#[derive(Debug, Default)]
pub struct Config {
    /// Flag name to values.
    values: BTreeMap<String, Vec<String>>,
}

// `connect` is a binary crate, so `pub` does not exempt an item from `dead_code`. The
// accessors below and `mapped_flags` are exercised only by this module's tests and by
// `main`'s guard test — which is the point of them, not an oversight.
#[cfg_attr(not(test), allow(dead_code))]
impl Config {
    /// Read a config file, refusing anything it cannot honour.
    pub fn load(path: &str) -> Result<Config> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}")).with_source(e)
        })?;
        Config::parse(&text, path)
    }

    /// Read the default config file if it happens to exist.
    ///
    /// Absent is not an error — most invocations are a person running one command. A
    /// file that exists but is broken **is** an error, because it was written on purpose.
    pub fn load_default(path: &str) -> Result<Option<Config>> {
        match std::fs::read_to_string(path) {
            Err(_) => Ok(None),
            Ok(text) => Config::parse(&text, path).map(Some),
        }
    }

    /// Parse and validate.
    pub fn parse(text: &str, source: &str) -> Result<Config> {
        let doc: toml::Value = toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("{source} is not valid TOML"))
                .with_source(e)
        })?;
        let table = doc.as_table().ok_or_else(|| {
            WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("{source} must be a table of sections"),
            )
        })?;

        let mut out = Config {
            values: BTreeMap::new(),
        };

        for (section, body) in table {
            if OWNED_ELSEWHERE.contains(&section.as_str()) {
                continue;
            }
            match body {
                toml::Value::Table(keys) => {
                    for (key, value) in keys {
                        out.absorb(source, &format!("{section}.{key}"), value)?;
                    }
                }
                // A top-level scalar. Allowed, mapped by its bare name, so a small file
                // does not need a section header to set `root`.
                other => out.absorb(source, section, other)?,
            }
        }
        Ok(out)
    }

    fn absorb(&mut self, source: &str, path: &str, value: &toml::Value) -> Result<()> {
        if let Some((_, why)) = UNIMPLEMENTED.iter().find(|(p, _)| *p == path) {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("{source}: `{path}` is not implemented — {why}"),
            ));
        }

        let flag = MAPPINGS
            .iter()
            .find(|m| m.path == path || m.flag == path)
            .map(|m| m.flag)
            .ok_or_else(|| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "{source}: unknown key `{path}`. A key that resolves to nothing \
                         reads as configured and does nothing, so it is refused rather \
                         than ignored. Known keys: {}",
                        MAPPINGS
                            .iter()
                            .map(|m| m.path)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            })?;

        let rendered = match value {
            toml::Value::String(s) => vec![s.clone()],
            toml::Value::Integer(i) => vec![i.to_string()],
            toml::Value::Boolean(b) => vec![b.to_string()],
            // A list becomes a repeated flag, which is how `--trusted-proxy` and
            // `--approver` already work.
            toml::Value::Array(items) => items
                .iter()
                .map(|i| match i {
                    toml::Value::String(s) => Ok(s.clone()),
                    toml::Value::Integer(n) => Ok(n.to_string()),
                    other => Err(WcError::with_detail(
                        Code::CONFIG_INVALID,
                        format!("{source}: `{path}` list holds a {}", other.type_str()),
                    )),
                })
                .collect::<Result<Vec<_>>>()?,
            other => {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "{source}: `{path}` is a {}; expected a string, number, boolean \
                         or list",
                        other.type_str()
                    ),
                ))
            }
        };
        self.values.insert(flag.to_string(), rendered);
        Ok(())
    }

    /// Values for a flag, if the file set it.
    #[must_use]
    pub fn get(&self, flag: &str) -> Option<&[String]> {
        self.values.get(flag).map(Vec::as_slice)
    }

    /// How many flags this file sets. No `is_empty` companion: nothing asks that
    /// question, and adding one to satisfy a lint would be a method with no caller.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }
}

/// The environment variable for a flag: `--anchor-interval` → `WARDEN_CONNECT_ANCHOR_INTERVAL`.
///
/// §8.13 promises `WARDEN_CONNECT_*` "for every key" and four were wired by hand. Derived
/// mechanically instead, so a new flag gets its environment variable by existing rather
/// than by somebody remembering.
#[must_use]
pub fn env_var_for(flag: &str) -> String {
    let mut name = String::from("WARDEN_CONNECT_");
    for c in flag.chars() {
        name.push(match c {
            '-' => '_',
            other => other.to_ascii_uppercase(),
        });
    }
    name
}

/// Fill `args` from the file and then from the environment.
///
/// Precedence is **flag over file over env**, which is §8.13's stated order and core's.
/// Implemented by filling only what is absent, in that sequence: a flag already present
/// is never touched, then the file, then the environment.
///
/// `known` is every flag name this invocation could accept, so the environment sweep does
/// not invent flags — reading `WARDEN_CONNECT_ANYTHING` into an unknown flag would trip
/// the unknown-flag check and blame the operator's command line for their environment.
pub fn apply(args: &mut Args, config: Option<&Config>, known: &[&str]) {
    if let Some(config) = config {
        for (flag, values) in &config.values {
            // Only what *this* command accepts. One `connect.toml` describes a whole
            // deployment, so it holds `listen` for `serve` beside `revocation_key` for
            // `quarantine`; injecting all of it into every command would make
            // `connect entities` fail the unknown-flag check because the file mentions a
            // listener. The file is a set of defaults, not a command line.
            if !known.contains(&flag.as_str()) {
                continue;
            }
            if !args.flags.contains_key(flag) {
                args.flags.insert(flag.clone(), values.clone());
            }
        }
    }
    for flag in known {
        if args.flags.contains_key(*flag) {
            continue;
        }
        if let Ok(value) = std::env::var(env_var_for(flag)) {
            if !value.is_empty() {
                args.flags.insert((*flag).to_string(), vec![value]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Environment variables are process-global and `cargo test` runs these on threads in
    /// one process, so a test that sets one is visible to every other test until it is
    /// removed. Two of these tests failed exactly that way before the lock existed —
    /// intermittently, which is the worst kind.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text, "test.toml")
    }

    #[test]
    fn a_mapped_key_becomes_a_flag() {
        let c = parse(
            r#"
            [server]
            listen = "0.0.0.0:8787"
            root = "/var/lib/warden-connect"
            [keys]
            kid = "k-2026-01"
            anchor_interval = 0
            "#,
        );
        // `anchor_interval` lives under [evidence], not [keys] — and being in the wrong
        // section has to be an error, not a near-miss that silently does nothing.
        assert!(
            c.is_err(),
            "a key in the wrong section must not be accepted"
        );

        let c = parse(
            r#"
            [server]
            listen = "0.0.0.0:8787"
            [keys]
            kid = "k-2026-01"
            [evidence]
            anchor_interval = 250
            "#,
        )
        .unwrap();
        assert_eq!(c.get("listen"), Some(&["0.0.0.0:8787".to_string()][..]));
        assert_eq!(c.get("kid"), Some(&["k-2026-01".to_string()][..]));
        assert_eq!(c.get("anchor-interval"), Some(&["250".to_string()][..]));
    }

    #[test]
    fn an_unknown_key_is_refused_with_the_known_ones_listed() {
        // The whole reason this module exists. A config file is version-controlled and
        // reviewed; a key in it that resolves to nothing is a false belief with an audit
        // trail behind it.
        let err = parse("[server]\nlisen = \"0.0.0.0:1\"\n").unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        let text = format!("{err}");
        assert!(text.contains("unknown key `server.lisen`"), "{text}");
        assert!(
            text.contains("reads as configured and does nothing"),
            "{text}"
        );
        assert!(
            text.contains("server.listen"),
            "and lists what is real: {text}"
        );
    }

    #[test]
    fn a_documented_but_unimplemented_key_says_so_and_says_why() {
        // §8.13 documents these. Accepting them silently would be worse than not having
        // a config file at all: `require_provenance = true` in a file nobody reads is a
        // deployment that believes it is stricter than it is.
        for (path, fragment) in [
            ("[policy]\nhot_reload = true\n", "needs a restart"),
            (
                "[admission]\nrequire_provenance = true\n",
                "stage 4 skipped",
            ),
            ("[policy]\npdp_url = \"https://pdp\"\n", "not implemented"),
            (
                "[server]\nmode = \"observe\"\n",
                "connect-mediate --observe",
            ),
        ] {
            let err = parse(path).unwrap_err();
            let text = format!("{err}");
            assert!(text.contains("is not implemented"), "{path}: {text}");
            assert!(text.contains(fragment), "{path}: {text}");
        }
    }

    #[test]
    fn sections_another_loader_owns_are_left_alone() {
        // `[[sink]]` and `[assurance]` are structured data read straight from this file
        // by their own loaders. "Handled elsewhere" and "does nothing" must be different
        // answers, or adding a sink would be refused by the flag layer.
        let c = parse(
            r#"
            [[sink]]
            name = "lake"
            format = "ocsf"
            transport = "webhook"
            endpoint = "https://x"

            [assurance]
            workers = 8

            [breakglass]
            max_ttl_secs = 3600

            [retention]
            contracts = "7y"

            [server]
            listen = "127.0.0.1:1"
            "#,
        )
        .unwrap();
        assert_eq!(c.len(), 1, "only the flag layer is absorbed");
        assert!(c.get("listen").is_some());
    }

    #[test]
    fn a_file_key_for_another_command_is_not_injected_into_this_one() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // One `connect.toml` describes a deployment: it holds `listen` for `serve` and
        // `revocation_key` for `quarantine`. If every command absorbed every key, then
        // `connect entities` would fail the unknown-flag check because the file mentions
        // a listener — an error about the operator's command line caused by their config.
        let c = parse("[server]\nlisten = \"0.0.0.0:1\"\n[keys]\nkid = \"k1\"\n").unwrap();
        let mut a = Args::parse(["entities".to_string()]);
        apply(&mut a, Some(&c), &["root", "tenant"]);
        assert!(a.flags.is_empty(), "{:?}", a.flags);

        // And is absorbed by a command that does accept it.
        let mut serve = Args::parse(["serve".to_string()]);
        apply(&mut serve, Some(&c), &["listen", "kid"]);
        assert_eq!(serve.get("listen"), Some("0.0.0.0:1"));
        assert_eq!(serve.get("kid"), Some("k1"));
    }

    #[test]
    fn precedence_is_flag_over_file_over_env() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // §8.13's stated order, and the one an operator relies on when overriding a
        // deployment's file for one invocation.
        let var = env_var_for("tenant");
        std::env::set_var(&var, "from-env");

        // env only
        let mut a = Args::parse(["entities".to_string()]);
        apply(&mut a, None, &["tenant"]);
        assert_eq!(a.get("tenant"), Some("from-env"));

        // file beats env
        let c = parse("[server]\ntenant = \"from-file\"\n").unwrap();
        let mut a = Args::parse(["entities".to_string()]);
        apply(&mut a, Some(&c), &["tenant"]);
        assert_eq!(a.get("tenant"), Some("from-file"));

        // flag beats both
        let mut a = Args::parse(
            ["entities", "--tenant", "from-flag"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        apply(&mut a, Some(&c), &["tenant"]);
        assert_eq!(a.get("tenant"), Some("from-flag"));

        std::env::remove_var(&var);
    }

    #[test]
    fn the_environment_sweep_only_fills_flags_this_command_knows() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // Otherwise a stray `WARDEN_CONNECT_WHATEVER` would become a flag and the
        // unknown-flag check would blame the operator's command line for their
        // environment — an error pointing at the wrong file.
        std::env::set_var("WARDEN_CONNECT_NOT_A_FLAG", "x");
        let mut a = Args::parse(["entities".to_string()]);
        apply(&mut a, None, &["tenant", "root"]);
        assert!(!a.flags.contains_key("not-a-flag"));
        std::env::remove_var("WARDEN_CONNECT_NOT_A_FLAG");
    }

    #[test]
    fn an_empty_environment_variable_does_not_override() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // `WARDEN_CONNECT_ROOT=` in a shell profile is how a variable gets unset in
        // practice; reading it as the empty path would put the estate in the process's
        // working directory.
        let var = env_var_for("root");
        std::env::set_var(&var, "");
        let mut a = Args::parse(["entities".to_string()]);
        apply(&mut a, None, &["root"]);
        assert!(a.get("root").is_none());
        std::env::remove_var(&var);
    }

    #[test]
    fn env_var_names_are_derived_not_remembered() {
        assert_eq!(env_var_for("root"), "WARDEN_CONNECT_ROOT");
        assert_eq!(
            env_var_for("anchor-interval"),
            "WARDEN_CONNECT_ANCHOR_INTERVAL"
        );
        assert_eq!(
            env_var_for("require-external-signing"),
            "WARDEN_CONNECT_REQUIRE_EXTERNAL_SIGNING"
        );
        // The four that were hand-wired before must keep the names they had, or an
        // existing deployment's environment stops being read.
        assert_eq!(env_var_for("tenant"), "WARDEN_CONNECT_TENANT");
    }

    #[test]
    fn a_list_becomes_a_repeated_flag() {
        let c = parse("[server]\ntrusted_proxy = [\"10.0.1.5\", \"10.0.1.6\"]\n").unwrap();
        assert_eq!(
            c.get("trusted-proxy"),
            Some(&["10.0.1.5".to_string(), "10.0.1.6".to_string()][..])
        );
    }

    #[test]
    fn a_wrong_typed_value_names_the_type_it_found() {
        // A table where a scalar belongs names what it found. This assertion originally
        // expected "unknown key" and was simply wrong: `server.listen` *is* known, and
        // saying so is more useful than pretending the key does not exist.
        let err = parse("[server]\nlisten = { host = \"x\" }\n").unwrap_err();
        assert!(format!("{err}").contains("is a table"), "{err}");

        let err = parse("[evidence]\nanchor_interval = 1.5\n").unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("is a float"), "{text}");
    }

    #[test]
    fn a_missing_default_file_is_not_an_error_but_a_broken_one_is() {
        assert!(Config::load_default("/nonexistent/connect.toml")
            .unwrap()
            .is_none());
        // An explicit --config that cannot be read is always an error: it was named.
        assert!(Config::load("/nonexistent/connect.toml").is_err());
    }
}

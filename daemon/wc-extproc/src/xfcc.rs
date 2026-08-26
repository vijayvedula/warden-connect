//! Peer identity from the transport.
//!
//! The one rule this module exists to enforce: an identity a caller can set is not an identity.
//! Envoy's `x-forwarded-client-cert` is only meaningful where Envoy itself strips any inbound
//! copy and re-sets it from the verified client certificate. Where that is not configured, the
//! header is caller-controlled and trusting it is worse than having no identity at all, because
//! it looks like authentication.
//!
//! `wc-core` already refuses a header-claimed identity with `WC-4020`; this is the parser for the
//! case where the gateway, not the caller, is the one asserting it.

/// The SPIFFE id from an XFCC header, if it carries one.
///
/// XFCC is a comma-separated list of `Key=Value;Key=Value` elements, one per hop. The FIRST
/// element is the one Envoy wrote for the directly-connected peer; later elements are hops
/// further out and are not this connection's peer. Reading the last element instead — which is
/// the easier mistake, because `split(',').last()` reads naturally — takes the identity of
/// whoever is furthest away and most able to lie about it.
#[must_use]
pub fn spiffe_from_xfcc(header: &str) -> Option<String> {
    let first = header.split(',').next()?;
    for kv in first.split(';') {
        let (k, v) = kv.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("URI") {
            let v = v.trim().trim_matches('"');
            if v.starts_with("spiffe://") {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uri_san_is_read_from_the_first_element() {
        let h = "By=spiffe://c/svc;Hash=abc;URI=spiffe://bank.example/ns/a/sa/caller";
        assert_eq!(
            spiffe_from_xfcc(h).as_deref(),
            Some("spiffe://bank.example/ns/a/sa/caller")
        );
    }

    #[test]
    fn a_later_hop_cannot_supply_the_identity() {
        // Two hops. The peer is the first; the second is further out. Taking the last element
        // would authenticate `attacker`.
        let h = "By=spiffe://c/x;URI=spiffe://bank.example/ns/a/sa/real,\
                 By=spiffe://c/y;URI=spiffe://bank.example/ns/a/sa/attacker";
        assert_eq!(
            spiffe_from_xfcc(h).as_deref(),
            Some("spiffe://bank.example/ns/a/sa/real")
        );
    }

    #[test]
    fn a_non_spiffe_uri_is_not_an_identity() {
        assert!(spiffe_from_xfcc("By=x;URI=https://example.com/who").is_none());
    }

    #[test]
    fn an_element_with_no_uri_yields_nothing() {
        assert!(spiffe_from_xfcc("By=spiffe://c/svc;Hash=abc").is_none());
        assert!(spiffe_from_xfcc("").is_none());
    }

    #[test]
    fn a_quoted_value_is_unwrapped() {
        assert_eq!(
            spiffe_from_xfcc(r#"URI="spiffe://bank.example/ns/a/sa/q""#).as_deref(),
            Some("spiffe://bank.example/ns/a/sa/q")
        );
    }
}

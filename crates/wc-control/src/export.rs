//! Regulatory registers and control evidence (`docs/08-lld.md` §8.5.9, UC-10).
//!
//! Every generator here is a pure function from a point-in-time projection to
//! bytes. That is not tidiness for its own sake — it is what makes an export
//! reproducible, which is what makes it defensible. Ask for the register as of
//! 30 June twice and you get the same bytes, because nothing in this module reads
//! a clock or touches the network.
//!
//! # The two things that make an export survive an audit
//!
//! **It references a signed checkpoint.** Every export embeds
//! `{ as_of, chain_head_seq, chain_head_hash, anchor_ref }`, so
//! `connect audit verify --export <file>` can prove the register describes the
//! estate the chain recorded, rather than whatever the database happened to say
//! when someone ran the report.
//!
//! **It declares its own gaps.** A register that says "these 14 parties are
//! unattested and these 3 mandatory DORA fields I cannot populate" is defensible.
//! One that emits blanks for them is not — and the blank is worse than the gap,
//! because it reads as a filed answer. So [`Exceptions`] is a required section of
//! every format, and the field-level gaps are enumerated by name rather than
//! summarised.
//!
//! # On the regulatory formats
//!
//! These are **DORA-shaped**, **CPS 230-shaped** and OSCAL-shaped exports built
//! from what a connection control plane knows. Several mandatory fields in the
//! real templates — LEI codes, annual contract value, country of a parent
//! undertaking — are facts about corporate entities that live in a procurement
//! system, not here. Those are listed in [`Exceptions::unpopulated_fields`] with
//! the table and field name, so whoever files the return knows exactly what they
//! still have to join in. Emitting an empty column and letting them find out
//! later is the failure mode this design refuses.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use wc_core::contract::{ContractRecord, ContractStatus};
use wc_core::error::{Code, Result, WcError};
use wc_core::model::{Entity, Lifecycle, Posture, TrustLevel};

use crate::store::Projection;

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// What ties an export to a signed point in the evidence chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The instant the register describes.
    pub as_of: u64,
    /// Chain sequence at that instant.
    pub chain_head_seq: u64,
    /// Chain head hash.
    pub chain_head_hash: String,
    /// The signed checkpoint covering the head, if one exists.
    ///
    /// `None` is reported, not hidden. An export with no anchor is still useful
    /// and is *not* independently verifiable, and those are different claims.
    #[serde(default)]
    pub anchor_ref: Option<String>,
    /// Whether the replay that built the projection reached a clean end.
    pub replay_complete: bool,
}

impl Provenance {
    /// Whether this export can be independently verified against a signature.
    #[must_use]
    pub fn is_verifiable(&self) -> bool {
        self.anchor_ref.is_some() && self.replay_complete
    }

    /// One line for a CSV comment row or a report header.
    #[must_use]
    pub fn caveat(&self) -> String {
        match (&self.anchor_ref, self.replay_complete) {
            (Some(a), true) => format!("verifiable against anchor {a}"),
            (Some(a), false) => format!(
                "anchor {a} present but the event replay was truncated; this register may be incomplete"
            ),
            (None, true) => {
                "NOT independently verifiable: no signed checkpoint covers this chain head"
                    .to_string()
            }
            (None, false) => {
                "NOT verifiable and the event replay was truncated; do not file this without investigating"
                    .to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

/// One declared gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exception {
    /// A stable machine-readable class, so a GRC platform can trend them.
    pub kind: String,
    /// What the gap is about — an entity id, a cid, or a table.field.
    pub subject: String,
    /// Why it is a gap, in the words a reviewer needs.
    pub detail: String,
}

/// A mandatory field this control plane cannot populate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpopulatedField {
    /// Which table or section.
    pub table: String,
    /// Which field.
    pub field: String,
    /// Where the filer has to get it instead.
    pub source: String,
}

/// Everything an export declines to assert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exceptions {
    /// Estate-level gaps: unattested parties, dangling references, and so on.
    pub gaps: Vec<Exception>,
    /// Mandatory template fields with no source in this system.
    pub unpopulated_fields: Vec<UnpopulatedField>,
}

impl Exceptions {
    /// Whether the register is complete on its own terms.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.gaps.is_empty() && self.unpopulated_fields.is_empty()
    }

    /// How many gaps of each kind, for a summary line.
    #[must_use]
    pub fn by_kind(&self) -> BTreeMap<String, usize> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for gap in &self.gaps {
            *counts.entry(gap.kind.clone()).or_insert(0) += 1;
        }
        counts
    }
}

/// Enumerate every estate-level gap in a projection.
///
/// Deliberately generous about what counts as a gap. The cost of naming something
/// that turns out to be fine is one line in a report; the cost of omitting
/// something is a regulatory finding.
#[must_use]
pub fn gaps(proj: &Projection, as_of: u64) -> Vec<Exception> {
    let mut out: Vec<Exception> = Vec::new();

    let mut ids: Vec<_> = proj.entities.keys().collect();
    ids.sort_by_key(|id| id.as_str());

    for id in ids {
        let e = &proj.entities[id];
        match e.posture {
            Posture::Attested => {}
            Posture::Unattested => out.push(Exception {
                kind: "party.unattested".to_string(),
                subject: e.id.as_str().to_string(),
                detail: "identity or provenance was never verified; the register lists this party but cannot vouch for it".to_string(),
            }),
            Posture::Degraded => out.push(Exception {
                kind: "party.degraded".to_string(),
                subject: e.id.as_str().to_string(),
                detail: format!("posture degraded (score {}); no renewal and no new contracts", e.posture_score),
            }),
            Posture::Quarantined => out.push(Exception {
                kind: "party.quarantined".to_string(),
                subject: e.id.as_str().to_string(),
                detail: "contained; every contract revoked and terminal until re-admission".to_string(),
            }),
        }
        if e.lifecycle == Lifecycle::Pending {
            out.push(Exception {
                kind: "party.never_activated".to_string(),
                subject: e.id.as_str().to_string(),
                detail: "registered but never activated, so it holds no contracts".to_string(),
            });
        }
        if e.pin.is_empty() {
            out.push(Exception {
                kind: "party.no_pin".to_string(),
                subject: e.id.as_str().to_string(),
                detail:
                    "no declared surface was pinned, so drift cannot be detected for this party"
                        .to_string(),
            });
        }
        if e.service.is_none() {
            // Without this, no register can say which business function fails.
            out.push(Exception {
                kind: "party.no_business_service".to_string(),
                subject: e.id.as_str().to_string(),
                detail:
                    "no business service recorded, so criticality cannot be mapped to a function"
                        .to_string(),
            });
        }
    }

    let mut cids: Vec<_> = proj.contracts.keys().collect();
    cids.sort_by_key(|c| c.as_str());
    for cid in cids {
        let c = &proj.contracts[cid];
        for (role, party) in [("caller", &c.caller), ("callee", &c.callee)] {
            if !proj.entities.contains_key(party) {
                out.push(Exception {
                    kind: "contract.dangling_party".to_string(),
                    subject: c.cid.as_str().to_string(),
                    detail: format!(
                        "{role} {party} is named by this contract but absent from the registry"
                    ),
                });
            }
        }
        if c.status == ContractStatus::Active && c.exp <= as_of {
            out.push(Exception {
                kind: "contract.expired_but_active".to_string(),
                subject: c.cid.as_str().to_string(),
                detail: format!(
                    "recorded Active but expired at {}; the record and the artifact disagree",
                    c.exp
                ),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The register envelope
// ---------------------------------------------------------------------------

/// One named table of rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    /// Template identifier, e.g. `RT.02.01`.
    pub id: String,
    /// What it holds.
    pub title: String,
    /// Column headers.
    pub columns: Vec<String>,
    /// Rows, aligned to `columns`.
    pub rows: Vec<Vec<String>>,
}

impl Table {
    /// Render as RFC 4180 CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        out.push_str(&csv_row(&self.columns));
        for row in &self.rows {
            out.push_str(&csv_row(row));
        }
        out
    }

    /// Assert every row matches the header width.
    ///
    /// A ragged table silently shifts every value one column left in whatever
    /// spreadsheet opens it, which is how a jurisdiction becomes a data class.
    fn check(&self) -> Result<()> {
        for (i, row) in self.rows.iter().enumerate() {
            if row.len() != self.columns.len() {
                return Err(WcError::with_detail(
                    Code::EXPORT_FAILED,
                    format!(
                        "{} row {} has {} values for {} columns",
                        self.id,
                        i + 1,
                        row.len(),
                        self.columns.len()
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_row(values: &[String]) -> String {
    let joined: Vec<String> = values.iter().map(|v| csv_field(v)).collect();
    format!("{}\n", joined.join(","))
}

/// A complete regulatory export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// Which register this is.
    pub format: String,
    /// The template revision this was shaped against.
    pub template: String,
    /// Point-in-time provenance.
    pub provenance: Provenance,
    /// The tables.
    pub tables: Vec<Table>,
    /// Declared gaps. Never optional.
    pub exceptions: Exceptions,
}

impl Register {
    /// Validate the whole register before anyone files it.
    pub fn check(&self) -> Result<()> {
        for table in &self.tables {
            table.check()?;
        }
        Ok(())
    }

    /// As one CSV document, tables separated by a comment header.
    ///
    /// The provenance and every exception are emitted as comment rows rather than
    /// dropped: a CSV that loses its caveats on the way to a spreadsheet is a CSV
    /// that gets filed without them.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {} · {}\n", self.format, self.template));
        out.push_str(&format!(
            "# as_of={} chain_head_seq={} chain_head_hash={}\n",
            self.provenance.as_of, self.provenance.chain_head_seq, self.provenance.chain_head_hash
        ));
        out.push_str(&format!("# {}\n", self.provenance.caveat()));
        if !self.exceptions.is_clean() {
            out.push_str(&format!(
                "# EXCEPTIONS: {} estate gap(s), {} unpopulated mandatory field(s) — see the sections below\n",
                self.exceptions.gaps.len(),
                self.exceptions.unpopulated_fields.len()
            ));
        }
        for table in &self.tables {
            out.push_str(&format!("\n# {} — {}\n", table.id, table.title));
            out.push_str(&table.to_csv());
        }
        out.push_str("\n# EXCEPTIONS — estate gaps\n");
        out.push_str(&csv_row(&[
            "kind".to_string(),
            "subject".to_string(),
            "detail".to_string(),
        ]));
        for gap in &self.exceptions.gaps {
            out.push_str(&csv_row(&[
                gap.kind.clone(),
                gap.subject.clone(),
                gap.detail.clone(),
            ]));
        }
        out.push_str("\n# EXCEPTIONS — mandatory fields with no source in this system\n");
        out.push_str(&csv_row(&[
            "table".to_string(),
            "field".to_string(),
            "obtain_from".to_string(),
        ]));
        for f in &self.exceptions.unpopulated_fields {
            out.push_str(&csv_row(&[
                f.table.clone(),
                f.field.clone(),
                f.source.clone(),
            ]));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Shared row helpers
// ---------------------------------------------------------------------------

fn s(value: impl AsRef<str>) -> String {
    value.as_ref().to_string()
}

/// Live contracts as of an instant, sorted for reproducibility.
fn live_contracts(proj: &Projection, as_of: u64) -> Vec<&ContractRecord> {
    let mut out: Vec<&ContractRecord> = proj
        .contracts
        .values()
        .filter(|c| c.iat <= as_of && c.exp > as_of && c.status == ContractStatus::Active)
        .collect();
    out.sort_by_key(|c| c.cid.as_str());
    out
}

fn sorted_entities(proj: &Projection) -> Vec<&Entity> {
    let mut out: Vec<&Entity> = proj.entities.values().collect();
    out.sort_by_key(|e| e.id.as_str());
    out
}

/// External parties: anything outside the internal trust level.
fn is_third_party(e: &Entity) -> bool {
    e.zone.trust_level() != TrustLevel::Internal
}

/// DORA criticality words from our tier, which is the mapping a filer will be
/// asked to justify — so it is one place, named.
fn criticality(tier: u8) -> &'static str {
    match tier {
        1 => "critical or important function",
        2 => "important function",
        3 => "supporting function",
        _ => "non-critical",
    }
}

// ---------------------------------------------------------------------------
// DORA
// ---------------------------------------------------------------------------

/// The DORA Register of Information template revision these tables are shaped
/// against.
pub const DORA_TEMPLATE: &str =
    "DORA RoI (ITS on the register of information) — RT.01–RT.07 shaped";

/// Mandatory DORA fields with no source in a connection control plane.
fn dora_unpopulated() -> Vec<UnpopulatedField> {
    [
        (
            "RT.01.01",
            "LEI of the entity maintaining the register",
            "corporate registry / treasury",
        ),
        ("RT.01.01", "Competent authority", "compliance"),
        (
            "RT.02.01",
            "Contract reference number",
            "procurement / CLM system",
        ),
        ("RT.02.01", "Annual expense or estimated cost", "finance"),
        (
            "RT.02.01",
            "Contract start and end date",
            "procurement / CLM system",
        ),
        (
            "RT.02.01",
            "Governing law of the contractual arrangement",
            "legal",
        ),
        (
            "RT.03.01",
            "LEI of the ICT third-party service provider",
            "procurement / corporate registry",
        ),
        (
            "RT.03.01",
            "Country of the provider's parent undertaking",
            "procurement",
        ),
        ("RT.03.01", "Person type / provider category", "procurement"),
        ("RT.05.01", "Total annual expense per provider", "finance"),
        (
            "RT.06.01",
            "Function identifier and licensed activity",
            "business architecture",
        ),
        (
            "RT.06.01",
            "Recovery time and recovery point objectives",
            "business continuity",
        ),
        (
            "RT.07.01",
            "Substitutability assessment and reintegration plan",
            "business continuity",
        ),
        (
            "RT.07.01",
            "Date of the last audit of the provider",
            "third-party risk",
        ),
    ]
    .iter()
    .map(|(table, field, source)| UnpopulatedField {
        table: s(table),
        field: s(field),
        source: s(source),
    })
    .collect()
}

/// Build a DORA-shaped Register of Information.
///
/// The rows warden-connect can actually populate: who the parties are, what each
/// connection permits, which business function it serves, the jurisdictions the
/// data may cross, and the approval that authorised it. What it cannot populate is
/// enumerated rather than blanked — see [`dora_unpopulated`].
pub fn dora_register(proj: &Projection, provenance: Provenance) -> Result<Register> {
    let as_of = provenance.as_of;
    let entities = sorted_entities(proj);
    let contracts = live_contracts(proj, as_of);

    // RT.02.01 — one row per contractual arrangement. A connection contract *is*
    // the arrangement here, which is the whole reason this export is cheap.
    let arrangements = Table {
        id: s("RT.02.01"),
        title: s("Contractual arrangements — general information"),
        columns: vec![
            s("contractual_arrangement_reference"),
            s("provider_identifier"),
            s("consuming_entity_identifier"),
            s("ict_service_type"),
            s("function_supported"),
            s("criticality"),
            s("start_date_unix"),
            s("end_date_unix"),
            s("approval_mode"),
            s("approved_by"),
            s("second_approver"),
            s("change_reference"),
            s("policy_version"),
        ],
        rows: contracts
            .iter()
            .map(|c| {
                let callee = proj.entities.get(&c.callee);
                vec![
                    c.cid.as_str().to_string(),
                    c.callee.as_str().to_string(),
                    c.caller.as_str().to_string(),
                    surface_summary(c),
                    callee
                        .and_then(|e| e.service.clone())
                        .unwrap_or_else(|| s("UNRECORDED — see exceptions")),
                    s(criticality(c.callee_tier.as_u8())),
                    c.iat.to_string(),
                    c.exp.to_string(),
                    format!("{:?}", c.approval.mode),
                    c.approval.by.as_ref().map_or_else(
                        || s("standing policy — no human"),
                        |h| h.as_str().to_string(),
                    ),
                    c.approval
                        .second
                        .as_ref()
                        .map_or_else(String::new, |h| h.as_str().to_string()),
                    c.approval.ticket.clone().unwrap_or_default(),
                    c.policy_version.clone(),
                ]
            })
            .collect(),
    };

    // RT.02.02 — the specific terms, which is where a connection contract carries
    // more than a procurement record ever does.
    let terms = Table {
        id: s("RT.02.02"),
        title: s("Contractual arrangements — specific terms per ICT service"),
        columns: vec![
            s("contractual_arrangement_reference"),
            s("contracted_surface"),
            s("data_classes"),
            s("jurisdictions"),
            s("max_calls_per_hour"),
            s("max_concurrent"),
            s("max_spend_usd_per_day"),
            s("human_oversight"),
            s("max_delegation_depth"),
            s("exit_path"),
        ],
        rows: contracts
            .iter()
            .map(|c| {
                vec![
                    c.cid.as_str().to_string(),
                    c.surface.items().join("|"),
                    c.terms.data_classes.join("|"),
                    c.terms.jurisdictions.join("|"),
                    opt_num(c.terms.max_calls_per_hour),
                    opt_num(c.terms.max_concurrent),
                    c.terms
                        .max_spend_usd_per_day
                        .map_or_else(String::new, |v| format!("{v:.2}")),
                    c.terms.human_oversight.clone().unwrap_or_default(),
                    c.terms.delegation.max_depth.to_string(),
                    // The exit path is not a policy document here — it is the
                    // expiry, which is enforced whether or not anyone reads it.
                    format!(
                        "contract expires at {}; revocable immediately by cid",
                        c.exp
                    ),
                ]
            })
            .collect(),
    };

    // RT.03.01 — providers. Only non-internal parties are third parties.
    let providers = Table {
        id: s("RT.03.01"),
        title: s("ICT third-party service providers"),
        columns: vec![
            s("provider_identifier"),
            s("zone"),
            s("trust_level"),
            s("criticality"),
            s("jurisdictions"),
            s("data_classes"),
            s("accountable_owner"),
            s("attestation_posture"),
            s("surface_pin"),
        ],
        rows: entities
            .iter()
            .filter(|e| is_third_party(e))
            .map(|e| {
                vec![
                    e.id.as_str().to_string(),
                    e.zone.as_str().to_string(),
                    format!("{:?}", e.zone.trust_level()),
                    s(criticality(e.tier.as_u8())),
                    e.jurisdictions.join("|"),
                    e.data_classes.join("|"),
                    e.owner.as_str().to_string(),
                    format!("{:?}", e.posture),
                    e.pin.manifest.clone(),
                ]
            })
            .collect(),
    };

    // RT.04.01 — the entities consuming those services.
    let consumers = Table {
        id: s("RT.04.01"),
        title: s("Entities making use of ICT services"),
        columns: vec![
            s("consuming_entity_identifier"),
            s("kind"),
            s("business_service"),
            s("zone"),
            s("accountable_owner"),
            s("criticality"),
            s("outbound_arrangements"),
        ],
        rows: entities
            .iter()
            .filter(|e| proj.by_caller.get(&e.id).is_some_and(|set| !set.is_empty()))
            .map(|e| {
                let count = proj.by_caller.get(&e.id).map_or(0, |set| set.len());
                vec![
                    e.id.as_str().to_string(),
                    format!("{:?}", e.kind),
                    e.service.clone().unwrap_or_else(|| s("UNRECORDED")),
                    e.zone.as_str().to_string(),
                    e.owner.as_str().to_string(),
                    s(criticality(e.tier.as_u8())),
                    count.to_string(),
                ]
            })
            .collect(),
    };

    // RT.06.01 — functions, aggregated from the business services we hold.
    let mut by_service: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for e in &entities {
        by_service
            .entry(e.service.clone().unwrap_or_else(|| s("UNRECORDED")))
            .or_default()
            .push(e);
    }
    let functions = Table {
        id: s("RT.06.01"),
        title: s("Functions supported by ICT services"),
        columns: vec![
            s("function_name"),
            s("highest_criticality"),
            s("party_count"),
            s("third_party_count"),
            s("jurisdictions"),
            s("data_classes"),
        ],
        rows: by_service
            .iter()
            .map(|(service, members)| {
                let tier = members.iter().map(|e| e.tier.as_u8()).min().unwrap_or(4);
                let jurisdictions: BTreeSet<&str> = members
                    .iter()
                    .flat_map(|e| e.jurisdictions.iter().map(String::as_str))
                    .collect();
                let classes: BTreeSet<&str> = members
                    .iter()
                    .flat_map(|e| e.data_classes.iter().map(String::as_str))
                    .collect();
                vec![
                    service.clone(),
                    s(criticality(tier)),
                    members.len().to_string(),
                    members
                        .iter()
                        .filter(|e| is_third_party(e))
                        .count()
                        .to_string(),
                    jurisdictions.into_iter().collect::<Vec<_>>().join("|"),
                    classes.into_iter().collect::<Vec<_>>().join("|"),
                ]
            })
            .collect(),
    };

    let register = Register {
        format: s("dora"),
        template: s(DORA_TEMPLATE),
        provenance,
        tables: vec![arrangements, terms, providers, consumers, functions],
        exceptions: Exceptions {
            gaps: gaps(proj, as_of),
            unpopulated_fields: dora_unpopulated(),
        },
    };
    register.check()?;
    Ok(register)
}

fn opt_num(v: Option<u32>) -> String {
    v.map_or_else(String::new, |n| n.to_string())
}

/// A short description of what a contract permits, for a register column.
fn surface_summary(c: &ContractRecord) -> String {
    let items = c.surface.items();
    let write = items.iter().any(|i| {
        let l = i.to_ascii_lowercase();
        [
            "write", "create", "delete", "update", "transfer", "wire", "post", "send",
        ]
        .iter()
        .any(|w| l.contains(w))
    });
    format!(
        "{} item(s), {}",
        items.len(),
        if write { "write-capable" } else { "read-only" }
    )
}

// ---------------------------------------------------------------------------
// APRA CPS 230
// ---------------------------------------------------------------------------

/// The CPS 230 shape these tables follow.
pub const CPS230_TEMPLATE: &str = "APRA CPS 230 — material service provider register, shaped";

fn cps230_unpopulated() -> Vec<UnpopulatedField> {
    [
        (
            "MSP",
            "Contract commencement and expiry",
            "procurement / CLM system",
        ),
        (
            "MSP",
            "Tolerance level for disruption",
            "business continuity",
        ),
        ("MSP", "Fourth-party reliance", "third-party risk"),
        (
            "MSP",
            "Board approval reference for material arrangements",
            "company secretary",
        ),
        (
            "CBS",
            "Critical operation tolerance (RTO / RPO / data loss)",
            "business continuity",
        ),
        ("CBS", "Nominated accountable executive", "operational risk"),
    ]
    .iter()
    .map(|(table, field, source)| UnpopulatedField {
        table: s(table),
        field: s(field),
        source: s(source),
    })
    .collect()
}

/// Build a CPS 230-shaped register.
///
/// CPS 230 asks a different question from DORA: not "list your arrangements" but
/// "which of your critical operations depend on a provider, and what happens when
/// one fails". So the primary table is keyed on the **business service**, with
/// providers hanging off it, rather than the other way round.
pub fn cps230_register(proj: &Projection, provenance: Provenance) -> Result<Register> {
    let as_of = provenance.as_of;
    let contracts = live_contracts(proj, as_of);
    let entities = sorted_entities(proj);

    let mut by_service: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut service_tier: BTreeMap<String, u8> = BTreeMap::new();
    for c in &contracts {
        let service = proj
            .entities
            .get(&c.caller)
            .and_then(|e| e.service.clone())
            .unwrap_or_else(|| s("UNRECORDED"));
        by_service
            .entry(service.clone())
            .or_default()
            .insert(c.callee.as_str().to_string());
        let tier = service_tier.entry(service).or_insert(4);
        *tier = (*tier).min(c.callee_tier.as_u8());
    }

    let operations = Table {
        id: s("CBS"),
        title: s("Critical business services and their provider dependencies"),
        columns: vec![
            s("business_service"),
            s("assessed_criticality"),
            s("provider_count"),
            s("providers"),
            s("material"),
        ],
        rows: by_service
            .iter()
            .map(|(service, providers)| {
                let tier = service_tier.get(service).copied().unwrap_or(4);
                vec![
                    service.clone(),
                    s(criticality(tier)),
                    providers.len().to_string(),
                    providers.iter().cloned().collect::<Vec<_>>().join("|"),
                    // Materiality under CPS 230 is a judgement, not a computation.
                    // Tier is the input; the answer is the institution's.
                    if tier <= 2 {
                        s("candidate — tier 1/2 dependency")
                    } else {
                        s("unlikely")
                    },
                ]
            })
            .collect(),
    };

    let providers = Table {
        id: s("MSP"),
        title: s("Service providers reached by a live arrangement"),
        columns: vec![
            s("provider"),
            s("zone"),
            s("trust_level"),
            s("offshore_jurisdictions"),
            s("data_classes"),
            s("accountable_owner"),
            s("attestation_posture"),
            s("live_arrangements"),
            s("surface_pin"),
        ],
        rows: entities
            .iter()
            .filter(|e| proj.by_callee.get(&e.id).is_some_and(|set| !set.is_empty()))
            .map(|e| {
                let live = contracts.iter().filter(|c| c.callee == e.id).count();
                vec![
                    e.id.as_str().to_string(),
                    e.zone.as_str().to_string(),
                    format!("{:?}", e.zone.trust_level()),
                    // Anything that is not AU is offshore for an APRA-regulated
                    // entity, and saying so is the filer's decision — we list the
                    // jurisdictions and let them apply it.
                    e.jurisdictions.join("|"),
                    e.data_classes.join("|"),
                    e.owner.as_str().to_string(),
                    format!("{:?}", e.posture),
                    live.to_string(),
                    e.pin.manifest.clone(),
                ]
            })
            .collect(),
    };

    let register = Register {
        format: s("cps230"),
        template: s(CPS230_TEMPLATE),
        provenance,
        tables: vec![operations, providers],
        exceptions: Exceptions {
            gaps: gaps(proj, as_of),
            unpopulated_fields: cps230_unpopulated(),
        },
    };
    register.check()?;
    Ok(register)
}

// ---------------------------------------------------------------------------
// OSCAL
// ---------------------------------------------------------------------------

/// OSCAL revision targeted.
pub const OSCAL_VERSION: &str = "1.1.2";

/// Build an OSCAL component-definition describing the estate as components.
///
/// Each party is a component; each live contract is a control implementation
/// statement on the caller, because "this agent may call exactly these two tools,
/// approved by this person, expiring then" *is* the control evidence a GRC
/// platform is asking for.
pub fn oscal_component(proj: &Projection, provenance: &Provenance) -> Result<Value> {
    let as_of = provenance.as_of;
    let entities = sorted_entities(proj);
    let contracts = live_contracts(proj, as_of);

    let components: Vec<Value> = entities
        .iter()
        .map(|e| {
            let implementations: Vec<Value> = contracts
                .iter()
                .filter(|c| c.caller == e.id)
                .map(|c| {
                    json!({
                        "uuid": uuid_from(c.cid.as_str()),
                        "source": format!("warden-connect:contract:{}", c.cid),
                        "description": format!(
                            "Connection to {} limited to {} until {}, approved {:?}{}.",
                            c.callee,
                            c.surface.items().join(", "),
                            c.exp,
                            c.approval.mode,
                            c.approval.by.as_ref().map_or(String::new(), |h| format!(" by {h}"))
                        ),
                        "props": [
                            { "name": "cid", "value": c.cid.as_str() },
                            { "name": "surface-digest", "value": c.surface_digest },
                            { "name": "policy-version", "value": c.policy_version },
                            { "name": "expires", "value": c.exp.to_string() },
                        ],
                        "implemented-requirements": [{
                            "uuid": uuid_from(&format!("{}:req", c.cid)),
                            "control-id": "ac-3",
                            "description": "Access enforced at the mediator against a signed, expiring connection contract."
                        }],
                    })
                })
                .collect();

            let mut component = json!({
                "uuid": uuid_from(e.id.as_str()),
                "type": match e.kind {
                    wc_core::model::Kind::Agent => "software",
                    _ => "service",
                },
                "title": e.id.as_str(),
                "description": format!(
                    "{:?} in zone {} at {}, owned by {}.",
                    e.kind, e.zone, criticality(e.tier.as_u8()), e.owner
                ),
                "props": [
                    { "name": "zone", "value": e.zone.as_str() },
                    { "name": "trust-level", "value": format!("{:?}", e.zone.trust_level()) },
                    { "name": "tier", "value": e.tier.as_u8().to_string() },
                    { "name": "posture", "value": format!("{:?}", e.posture) },
                    { "name": "posture-score", "value": e.posture_score.to_string() },
                    { "name": "surface-pin", "value": e.pin.manifest.clone() },
                ],
                "responsible-roles": [{
                    "role-id": "asset-owner",
                    "party-uuids": [uuid_from(e.owner.as_str())],
                }],
            });
            if !implementations.is_empty() {
                component["control-implementations"] = Value::Array(implementations);
            }
            component
        })
        .collect();

    Ok(json!({
        "component-definition": {
            "uuid": uuid_from(&format!("wc:{}:{}", provenance.chain_head_hash, as_of)),
            "metadata": {
                "title": "warden-connect estate — agent connection controls",
                "last-modified": iso8601(as_of),
                "version": provenance.chain_head_seq.to_string(),
                "oscal-version": OSCAL_VERSION,
                "props": [
                    { "name": "as-of", "value": as_of.to_string() },
                    { "name": "chain-head-seq", "value": provenance.chain_head_seq.to_string() },
                    { "name": "chain-head-hash", "value": provenance.chain_head_hash },
                    { "name": "anchor-ref", "value": provenance.anchor_ref.clone().unwrap_or_else(|| s("none")) },
                    { "name": "verifiable", "value": provenance.is_verifiable().to_string() },
                ],
                "remarks": provenance.caveat(),
            },
            "components": components,
            // Gaps travel with the evidence, not in a covering email.
            "back-matter": {
                "resources": [{
                    "uuid": uuid_from(&format!("exceptions:{as_of}")),
                    "title": "Declared exceptions",
                    "description": "Estate gaps and mandatory fields with no source in this system.",
                    "props": gaps(proj, as_of)
                        .iter()
                        .map(|g| json!({ "name": g.kind, "value": g.subject, "remarks": g.detail }))
                        .collect::<Vec<_>>(),
                }],
            },
        }
    }))
}

/// A CycloneDX 1.6 BOM of one party's declared surface.
///
/// The useful framing: a tool surface is a dependency list. Each contracted item
/// is a component with its own pin, so a consumer can diff two BOMs and see
/// exactly which tool's text changed.
pub fn cyclonedx_bom(e: &Entity, as_of: u64) -> Result<Value> {
    if e.pin.is_empty() {
        return Err(WcError::with_detail(
            Code::EXPORT_FAILED,
            format!("{} has no pinned surface, so it has no BOM", e.id),
        ));
    }
    let components: Vec<Value> = e
        .pin
        .items
        .iter()
        .map(|(name, digest)| {
            json!({
                "type": "library",
                "bom-ref": format!("{}#{}", e.id, name),
                "name": name,
                "hashes": [{
                    "alg": "SHA-256",
                    "content": digest.strip_prefix("sha256:").unwrap_or(digest),
                }],
            })
        })
        .collect();

    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": iso8601(as_of),
            "component": {
                "type": "application",
                "bom-ref": e.id.as_str(),
                "name": e.id.as_str(),
                "hashes": [{
                    "alg": "SHA-256",
                    "content": e.pin.manifest.strip_prefix("sha256:").unwrap_or(&e.pin.manifest),
                }],
            },
            "properties": [
                { "name": "warden-connect:zone", "value": e.zone.as_str() },
                { "name": "warden-connect:tier", "value": e.tier.as_u8().to_string() },
                { "name": "warden-connect:posture", "value": format!("{:?}", e.posture) },
                { "name": "warden-connect:owner", "value": e.owner.as_str() },
            ],
        },
        "components": components,
    }))
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

/// A deterministic RFC 4122-shaped identifier derived from a name.
///
/// Deterministic rather than random: OSCAL consumers key on uuids, so the same
/// estate exported twice must produce the same document or every diff is noise.
/// Version nibble 5 (name-based), which is what this actually is.
#[must_use]
pub fn uuid_from(name: &str) -> String {
    let h = wc_core::util::sha256_hex(name);
    format!(
        "{}-{}-5{}-{}{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        // Variant bits: one of 8, 9, a, b.
        match &h[16..17] {
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => "8",
            "8" | "9" | "a" | "b" => &h[16..17],
            _ => "9",
        },
        &h[17..20],
        &h[20..32]
    )
}

/// Unix seconds as an ISO 8601 instant, UTC.
///
/// Hand-rolled because pulling a date library in for one format string is not a
/// trade this dependency budget makes. Proleptic Gregorian, which is correct for
/// every timestamp this system can hold.
#[must_use]
pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`, shifted to the Unix epoch.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wc_core::contract::{ApprovalMode, ApprovalRef, Surface, Terms, CONTRACT_SCHEMA};
    use wc_core::model::{Cid, EntityId, HumanRef, Jti, Kind, Pin, Tier, ZoneId, PIN_ALG};

    const AS_OF: u64 = 1_800_000_000;

    fn id(name: &str) -> EntityId {
        EntityId::new(format!("spiffe://org/ns/x/sa/{name}")).unwrap()
    }

    fn pin(items: &[&str]) -> Pin {
        Pin {
            alg: PIN_ALG.to_string(),
            manifest: s("sha256:m1"),
            items: items
                .iter()
                .map(|n| ((*n).to_string(), format!("sha256:{n}")))
                .collect(),
            pinned_at: AS_OF - 1_000,
        }
    }

    fn entity(name: &str, zone: &str, tier: u8, service: Option<&str>) -> Entity {
        let mut e = Entity::pending(
            id(name),
            Kind::McpServer,
            HumanRef::new("human:priya@org").unwrap(),
            ZoneId::new(zone).unwrap(),
            Tier::new(tier).unwrap(),
            AS_OF - 2_000,
        );
        e.lifecycle = Lifecycle::Active;
        e.posture = Posture::Attested;
        e.posture_score = 95;
        e.service = service.map(s);
        e.jurisdictions = vec![s("SG"), s("AU")];
        e.data_classes = vec![s("financial")];
        e.pin = pin(&["get_balance", "list_transactions"]);
        e
    }

    fn contract(n: u32, caller: &str, callee: &str, tools: &[&str], tier: u8) -> ContractRecord {
        ContractRecord {
            cid: Cid::new(format!("conn_{n:08x}")).unwrap(),
            jti: Jti::new("jti_0123456789abcdef").unwrap(),
            caller: id(caller),
            callee: id(callee),
            caller_zone: ZoneId::new("internal.apac-ops").unwrap(),
            callee_zone: ZoneId::new("internal.payments").unwrap(),
            callee_tier: Tier::new(tier).unwrap(),
            callee_manifest: s("sha256:m1"),
            surface_digest: s("sha256:sd"),
            surface: Surface {
                tools: tools.iter().map(s).collect(),
                ..Surface::default()
            },
            terms: Terms {
                data_classes: vec![s("financial")],
                jurisdictions: vec![s("SG")],
                max_calls_per_hour: Some(600),
                human_oversight: Some(s("required_above:10000_usd")),
                ..Terms::default()
            },
            aud: vec![s("warden:mediator:apac")],
            jws_sha256: s("sha256:aa"),
            status: ContractStatus::Active,
            approval: ApprovalRef {
                by: Some(HumanRef::new("human:cecil").unwrap()),
                jti: None,
                ticket: Some(s("RISK-14")),
                mode: ApprovalMode::Human,
                second: None,
                merges: Vec::new(),
            },
            policy_version: s("connect-policy@v9"),
            iat: AS_OF - 1_000,
            exp: AS_OF + 86_400,
            schema: CONTRACT_SCHEMA,
        }
    }

    fn projection(entities: Vec<Entity>, contracts: Vec<ContractRecord>) -> Projection {
        let mut p = Projection::default();
        for e in entities {
            p.entities.insert(e.id.clone(), e);
        }
        for c in contracts {
            p.by_caller
                .entry(c.caller.clone())
                .or_default()
                .insert(c.cid.clone());
            p.by_callee
                .entry(c.callee.clone())
                .or_default()
                .insert(c.cid.clone());
            p.contracts.insert(c.cid.clone(), c);
        }
        p
    }

    fn provenance(anchor: Option<&str>) -> Provenance {
        Provenance {
            as_of: AS_OF,
            chain_head_seq: 42,
            chain_head_hash: s("sha256:head"),
            anchor_ref: anchor.map(s),
            replay_complete: true,
        }
    }

    fn estate() -> Projection {
        projection(
            vec![
                entity("recon", "internal.apac-ops", 3, Some("payments-recon")),
                entity("payments", "internal.payments", 2, Some("payments-core")),
                entity("acme", "partner.acme", 1, Some("fx-settlement")),
            ],
            vec![
                contract(1, "recon", "payments", &["get_balance"], 2),
                contract(2, "recon", "acme", &["post_settlement"], 1),
            ],
        )
    }

    // --- provenance --------------------------------------------------------

    #[test]
    fn an_export_without_an_anchor_says_it_is_not_verifiable() {
        // "Not independently verifiable" and "verified" are different claims, and
        // an export that blurs them is worse than one that has no anchor at all.
        let p = provenance(None);
        assert!(!p.is_verifiable());
        assert!(p.caveat().contains("NOT independently verifiable"));

        let anchored = provenance(Some("anchor:seq-40"));
        assert!(anchored.is_verifiable());
        assert!(anchored.caveat().contains("anchor:seq-40"));
    }

    #[test]
    fn a_truncated_replay_is_never_silently_filed() {
        let p = Provenance {
            replay_complete: false,
            ..provenance(Some("anchor:seq-40"))
        };
        assert!(!p.is_verifiable());
        assert!(p.caveat().contains("truncated"));

        let neither = Provenance {
            replay_complete: false,
            ..provenance(None)
        };
        assert!(neither.caveat().contains("do not file this"));
    }

    // --- exceptions --------------------------------------------------------

    #[test]
    fn every_kind_of_estate_gap_is_named() {
        let mut unattested = entity("ghost", "internal.apac-ops", 3, Some("svc"));
        unattested.posture = Posture::Unattested;
        let mut degraded = entity("drifty", "internal.apac-ops", 3, Some("svc"));
        degraded.posture = Posture::Degraded;
        degraded.posture_score = 60;
        let mut quarantined = entity("bad", "internal.apac-ops", 3, Some("svc"));
        quarantined.posture = Posture::Quarantined;
        let mut pending = entity("new", "internal.apac-ops", 3, Some("svc"));
        pending.lifecycle = Lifecycle::Pending;
        let mut unpinned = entity("nopin", "internal.apac-ops", 3, Some("svc"));
        unpinned.pin = Pin::empty(AS_OF - 2_000);
        let no_service = entity("orphan", "internal.apac-ops", 3, None);

        let proj = projection(
            vec![
                unattested,
                degraded,
                quarantined,
                pending,
                unpinned,
                no_service,
            ],
            vec![],
        );
        let kinds = Exceptions {
            gaps: gaps(&proj, AS_OF),
            ..Exceptions::default()
        }
        .by_kind();

        for expected in [
            "party.unattested",
            "party.degraded",
            "party.quarantined",
            "party.never_activated",
            "party.no_pin",
            "party.no_business_service",
        ] {
            assert!(
                kinds.contains_key(expected),
                "missing {expected}: {kinds:?}"
            );
        }
    }

    #[test]
    fn a_dangling_contract_party_is_a_declared_gap() {
        // Silently omitting it would make the register look complete while a live
        // contract points at a party nobody governs.
        let mut proj = estate();
        proj.entities.remove(&id("acme"));
        let found = gaps(&proj, AS_OF);
        assert!(
            found
                .iter()
                .any(|g| g.kind == "contract.dangling_party" && g.detail.contains("acme")),
            "{found:?}"
        );
    }

    #[test]
    fn a_contract_recorded_active_past_its_expiry_is_a_gap() {
        let mut proj = estate();
        let cid = Cid::new("conn_00000001").unwrap();
        proj.contracts.get_mut(&cid).unwrap().exp = AS_OF - 1;
        let found = gaps(&proj, AS_OF);
        assert!(
            found
                .iter()
                .any(|g| g.kind == "contract.expired_but_active"),
            "{found:?}"
        );
    }

    #[test]
    fn a_clean_estate_has_no_gaps() {
        let found = gaps(&estate(), AS_OF);
        assert!(found.is_empty(), "{found:?}");
    }

    // --- DORA --------------------------------------------------------------

    #[test]
    fn a_dora_register_carries_every_table_and_declares_its_gaps() {
        let r = dora_register(&estate(), provenance(Some("anchor:40"))).unwrap();
        let ids: Vec<&str> = r.tables.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["RT.02.01", "RT.02.02", "RT.03.01", "RT.04.01", "RT.06.01"]
        );

        // Only the partner is a third party; internal parties are not.
        let providers = r.tables.iter().find(|t| t.id == "RT.03.01").unwrap();
        assert_eq!(providers.rows.len(), 1);
        assert!(providers.rows[0][0].contains("acme"));

        // Mandatory fields with no source here are enumerated, never blanked.
        assert!(!r.exceptions.unpopulated_fields.is_empty());
        assert!(r
            .exceptions
            .unpopulated_fields
            .iter()
            .any(|f| f.field.contains("LEI")));
    }

    #[test]
    fn dora_rows_carry_the_approval_that_authorised_each_arrangement() {
        // The point of the whole system, in one register column: the approval is
        // the enforcement, so it is a field rather than a filed ticket.
        let r = dora_register(&estate(), provenance(Some("anchor:40"))).unwrap();
        let t = r.tables.iter().find(|t| t.id == "RT.02.01").unwrap();
        let approved_by = t.columns.iter().position(|c| c == "approved_by").unwrap();
        let change_ref = t
            .columns
            .iter()
            .position(|c| c == "change_reference")
            .unwrap();
        assert!(t.rows.iter().all(|row| row[approved_by] == "human:cecil"));
        assert!(t.rows.iter().all(|row| row[change_ref] == "RISK-14"));
    }

    #[test]
    fn standing_issuance_says_so_rather_than_leaving_the_approver_blank() {
        let mut proj = estate();
        let cid = Cid::new("conn_00000001").unwrap();
        proj.contracts.get_mut(&cid).unwrap().approval = ApprovalRef::standing();
        let r = dora_register(&proj, provenance(None)).unwrap();
        let t = r.tables.iter().find(|t| t.id == "RT.02.01").unwrap();
        let col = t.columns.iter().position(|c| c == "approved_by").unwrap();
        assert!(t
            .rows
            .iter()
            .any(|row| row[col] == "standing policy — no human"));
    }

    #[test]
    fn only_live_contracts_appear_and_the_as_of_is_respected() {
        let mut proj = estate();
        let cid = Cid::new("conn_00000002").unwrap();
        proj.contracts.get_mut(&cid).unwrap().exp = AS_OF - 1;
        let r = dora_register(&proj, provenance(None)).unwrap();
        let t = r.tables.iter().find(|t| t.id == "RT.02.01").unwrap();
        assert_eq!(t.rows.len(), 1, "the expired arrangement is not live");
    }

    #[test]
    fn a_register_is_reproducible() {
        // Ask for the same instant twice and get the same bytes, or no auditor can
        // check anybody's working.
        let proj = estate();
        let a = dora_register(&proj, provenance(Some("anchor:40")))
            .unwrap()
            .to_csv();
        let b = dora_register(&proj, provenance(Some("anchor:40")))
            .unwrap()
            .to_csv();
        assert_eq!(a, b);
    }

    // --- CSV rendering -----------------------------------------------------

    #[test]
    fn csv_quotes_the_characters_that_would_break_a_row() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn a_ragged_table_is_refused() {
        // A short row shifts every later value one column left in whatever opens
        // it, which is how a jurisdiction becomes a data class.
        let bad = Table {
            id: s("RT.02.01"),
            title: s("t"),
            columns: vec![s("a"), s("b")],
            rows: vec![vec![s("only-one")]],
        };
        let err = bad.check().unwrap_err();
        assert_eq!(err.code(), Code::EXPORT_FAILED);
        assert!(err.to_string().contains("1 values for 2 columns"));
    }

    #[test]
    fn the_csv_document_carries_provenance_and_exceptions_as_comments() {
        // A CSV that loses its caveats on the way into a spreadsheet is a CSV that
        // gets filed without them.
        let mut proj = estate();
        proj.entities.get_mut(&id("payments")).unwrap().posture = Posture::Unattested;
        let csv = dora_register(&proj, provenance(None)).unwrap().to_csv();

        assert!(csv.contains("# as_of=1800000000 chain_head_seq=42"));
        assert!(csv.contains("NOT independently verifiable"));
        assert!(csv.contains("# EXCEPTIONS: "));
        assert!(csv.contains("party.unattested"));
        assert!(csv.contains("obtain_from"));
    }

    // --- CPS 230 -----------------------------------------------------------

    #[test]
    fn cps230_is_keyed_on_the_business_service_not_the_provider() {
        // CPS 230 asks which critical operations depend on a provider, which is the
        // opposite orientation from DORA.
        let r = cps230_register(&estate(), provenance(Some("anchor:40"))).unwrap();
        let cbs = r.tables.iter().find(|t| t.id == "CBS").unwrap();
        assert_eq!(cbs.columns[0], "business_service");
        assert_eq!(cbs.rows.len(), 1, "both contracts belong to payments-recon");
        assert_eq!(cbs.rows[0][0], "payments-recon");
        assert_eq!(cbs.rows[0][2], "2", "two providers");
        assert!(cbs.rows[0][4].contains("candidate"), "tier 1 dependency");
    }

    #[test]
    fn materiality_is_offered_as_a_candidate_not_asserted() {
        // Materiality under CPS 230 is the institution's judgement. Tier is the
        // input; claiming the answer would be the export overreaching.
        let proj = projection(
            vec![
                entity("recon", "internal.apac-ops", 4, Some("reporting")),
                entity("cache", "internal.apac-ops", 4, Some("reporting")),
            ],
            vec![contract(1, "recon", "cache", &["get"], 4)],
        );
        let r = cps230_register(&proj, provenance(None)).unwrap();
        let cbs = r.tables.iter().find(|t| t.id == "CBS").unwrap();
        assert_eq!(cbs.rows[0][4], "unlikely");
    }

    // --- OSCAL and BOM -----------------------------------------------------

    #[test]
    fn oscal_carries_contracts_as_control_implementations() {
        let doc = oscal_component(&estate(), &provenance(Some("anchor:40"))).unwrap();
        let cd = &doc["component-definition"];
        assert_eq!(cd["metadata"]["oscal-version"], OSCAL_VERSION);
        assert_eq!(cd["components"].as_array().unwrap().len(), 3);

        let recon = cd["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["title"].as_str().unwrap().contains("recon"))
            .unwrap();
        let impls = recon["control-implementations"].as_array().unwrap();
        assert_eq!(impls.len(), 2);
        assert!(impls[0]["description"]
            .as_str()
            .unwrap()
            .contains("limited to"));

        // A component with no outbound contracts carries no implementations rather
        // than an empty array that reads as "no controls".
        let payments = cd["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["title"].as_str().unwrap().contains("payments"))
            .unwrap();
        assert!(payments.get("control-implementations").is_none());
    }

    #[test]
    fn oscal_metadata_states_whether_it_is_verifiable() {
        let doc = oscal_component(&estate(), &provenance(None)).unwrap();
        let props = doc["component-definition"]["metadata"]["props"]
            .as_array()
            .unwrap();
        let verifiable = props.iter().find(|p| p["name"] == "verifiable").unwrap();
        assert_eq!(verifiable["value"], "false");
        assert!(doc["component-definition"]["metadata"]["remarks"]
            .as_str()
            .unwrap()
            .contains("NOT independently verifiable"));
    }

    #[test]
    fn oscal_gaps_travel_with_the_evidence() {
        let mut proj = estate();
        proj.entities.get_mut(&id("payments")).unwrap().posture = Posture::Degraded;
        let doc = oscal_component(&proj, &provenance(Some("a"))).unwrap();
        let resources = doc["component-definition"]["back-matter"]["resources"]
            .as_array()
            .unwrap();
        let props = resources[0]["props"].as_array().unwrap();
        assert!(props.iter().any(|p| p["name"] == "party.degraded"));
    }

    #[test]
    fn uuids_are_deterministic_and_well_shaped() {
        // OSCAL consumers key on uuids, so the same estate exported twice must
        // produce the same document or every diff is noise.
        let a = uuid_from("spiffe://org/ns/x/sa/recon");
        assert_eq!(a, uuid_from("spiffe://org/ns/x/sa/recon"));
        assert_ne!(a, uuid_from("spiffe://org/ns/x/sa/other"));

        let parts: Vec<&str> = a.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "{a}"
        );
        assert!(a.chars().nth(14) == Some('5'), "version nibble: {a}");
        assert!(
            matches!(a.chars().nth(19), Some('8' | '9' | 'a' | 'b')),
            "variant nibble: {a}"
        );
    }

    #[test]
    fn a_bom_lists_every_pinned_item_with_its_digest() {
        let e = entity("payments", "internal.payments", 2, Some("payments-core"));
        let bom = cyclonedx_bom(&e, AS_OF).unwrap();
        assert_eq!(bom["specVersion"], "1.6");
        let components = bom["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0]["name"], "get_balance");
        assert_eq!(components[0]["hashes"][0]["content"], "get_balance");
        assert_eq!(bom["metadata"]["component"]["hashes"][0]["content"], "m1");
    }

    #[test]
    fn a_party_with_no_pin_has_no_bom() {
        let mut e = entity("nopin", "internal.payments", 2, Some("svc"));
        e.pin = Pin::empty(AS_OF - 2_000);
        assert_eq!(
            cyclonedx_bom(&e, AS_OF).unwrap_err().code(),
            Code::EXPORT_FAILED
        );
    }

    // --- dates -------------------------------------------------------------

    #[test]
    fn iso8601_is_correct_across_the_awkward_cases() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_800_000_000), "2027-01-15T08:00:00Z");
        // Leap day, and the day after.
        assert_eq!(iso8601(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(iso8601(1_709_251_200), "2024-03-01T00:00:00Z");
        // A non-leap century boundary, which is where naive formulas break.
        assert_eq!(iso8601(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(iso8601(86_399), "1970-01-01T23:59:59Z");
    }
}

//! The read-only portal (`connect serve --portal`).
//!
//! # Why it is read-only, and why that is not a limitation
//!
//! Every write in this system already has an approval mechanism: a pull request, reviewed and
//! merged, in a repository somebody owns. A portal button that minted or approved would be a
//! **second consent path for the same decision** — two mechanisms, one meaning, and eventual drift
//! between them. It would also need an authorization model of its own, built from nothing, to decide
//! who may press it.
//!
//! So the portal explains and the CLI executes. Its most useful screen is not a form, it is the
//! command it hands you: pick a server and some tools, and it writes the `warden/needs.toml` and the
//! `connect need apply` line. Discovery, then implementation.
//!
//! # Server-rendered on purpose
//!
//! The data is embedded in the page rather than fetched by it. A browser has no bearer token, and
//! the alternatives are all worse: a token in a query string ends up in access logs, and a token in
//! JavaScript is a token handed to every extension in the browser. Rendering server-side means the
//! only credential involved is the one on the request that asked for the page, which an
//! authenticating proxy supplies exactly as it does for every other route.
//!
//! **Consequence worth stating:** `?as=` selects whose catalogue you are looking at, and this route
//! is gated by the `read` role like the rest of the API. That makes the portal a **platform
//! operator's** tool — somebody who already holds `read` can already query any consumer's view over
//! `/v1/offers`. If it is ever put in front of consumers directly, `as` must be bound to their
//! authenticated identity by the proxy, not chosen in a query string.
//!
//! # No dependencies
//!
//! One file, inline CSS and script, no images, no fonts, no fetches. The CSP on the response says
//! the same thing (`default-src 'none'`), so a future edit that reaches for a CDN fails in the
//! browser rather than silently working in development and being blocked in production.

use std::collections::BTreeMap;

use crate::chain;
use crate::inventory::{Inventory, NEEDS_PATH};
use crate::issuance::{PendingRequest, RequestStatus};
use crate::offer::CatalogueEntry;
use wc_core::contract::ContractRecord;
use wc_core::model::{Entity, EntityId, Lifecycle, Posture};

/// Escape text for HTML.
///
/// Applied to **every** interpolated value without exception, including ones that look safe. Entity
/// ids are validated, but repository names, tool names and owner strings arrive from a source host
/// or a scan, and "this one cannot contain a quote" is the assumption that ends with a page that
/// executes a tool name. Cheaper to escape everything than to maintain a list of what is trusted.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Everything one page render needs, gathered by the caller from the projection.
///
/// A plain struct rather than the store itself, so rendering is a pure function of its input and can
/// be tested without a control plane. The route does the reading; this does the writing.
pub struct View<'a> {
    /// Who the catalogue is being shown for, if a consumer was named.
    pub as_consumer: Option<&'a Entity>,
    /// That consumer's catalogue, already filtered by audience.
    pub catalogue: Vec<CatalogueEntry>,
    /// Registered parties, for the consumer picker.
    pub entities: Vec<&'a Entity>,
    /// Requests still awaiting a decision, and who each is waiting on.
    pub pending: Vec<(&'a PendingRequest, Option<&'a Entity>)>,
    /// The last discovery sweep, when one was supplied and could be read.
    pub inventory: Option<&'a Inventory>,
    /// Why the sweep could not be read, when one was configured and failed.
    ///
    /// Separate from `inventory: None`, and that separation is the point. Swallowing the error made
    /// an unreadable or malformed file render exactly like no file at all — so a stale token, a
    /// truncated write or a schema change would show "no sweep supplied" and an operator would go
    /// looking for a flag they had already passed. "I looked and could not" must never read the same
    /// as "there was nothing to look at"; `file_if_present` carries the same warning for the same
    /// reason, and this code repeated the mistake anyway.
    pub inventory_error: Option<String>,
    /// Which registered servers the sweep's targets map to, so shadow rows can be told apart.
    pub known_targets: BTreeMap<String, EntityId>,
    /// Per-provider impact of the terms now in force: who breaks, and how.
    ///
    /// Computed by the route from [`crate::offer::impact`], which is the same function
    /// `offer status` uses. Two implementations of "who does this affect" would eventually
    /// disagree, and the one on the page is the one a provider would act on.
    pub impacts: Vec<(EntityId, crate::offer::Impact)>,
    /// A connection being looked up, with its record and its evidence rows.
    ///
    /// `Some((cid, None, rows))` is a cid that is not in the register — reported as such rather than
    /// as an empty result, because "no such connection" and "a connection with no evidence" are
    /// different answers and only one of them is alarming.
    pub lookup: Option<(String, Option<&'a ContractRecord>, Vec<&'a chain::Entry>)>,
    /// Live contract count, for the header.
    pub contracts: usize,
    /// The issuer this plane mints as.
    pub iss: &'a str,
}

const CSS: &str = "\
:root{--bg:#f4f5f8;--card:#fff;--ink:#1a1e2e;--soft:#565e73;--faint:#868da0;--line:#d5d9e3;\
--accent:#2e3f86;--ok:#1d6a55;--okbg:#e2f0eb;--warn:#8a6516;--warnbg:#f6efdc;--deny:#9c3427;\
--denybg:#f7e8e5;--code:#14172a;--codefg:#d9ddea}\
@media(prefers-color-scheme:dark){:root{--bg:#101320;--card:#171b2a;--ink:#e5e8f0;--soft:#a4acc0;\
--faint:#737b90;--line:#2a3044;--accent:#8da2e8;--ok:#6fc4a8;--okbg:#15302a;--warn:#d9b061;\
--warnbg:#302614;--deny:#e08a7c;--denybg:#331d1a;--code:#0a0d17;--codefg:#d9ddea}}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,\
'Segoe UI',Roboto,Helvetica,Arial,sans-serif}\
.wrap{max-width:62rem;margin:0 auto;padding:2rem 1.25rem 5rem}\
h1{font:600 1.9rem/1.15 ui-serif,Georgia,serif;letter-spacing:-.02em;margin:0 0 .3rem}\
h2{font:600 1.25rem/1.2 ui-serif,Georgia,serif;margin:2.4rem 0 .3rem}\
.sub{color:var(--soft);margin:0 0 2rem}\
.lede{color:var(--soft);margin:.2rem 0 1rem}\
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:1rem 1.1rem;\
margin:0 0 1rem}\
table{border-collapse:collapse;width:100%;font-size:.9rem}\
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:6px;background:var(--card);\
margin:0 0 1rem}\
th{text-align:left;font:500 .68rem/1.4 ui-monospace,Menlo,monospace;letter-spacing:.1em;\
text-transform:uppercase;color:var(--faint);padding:.6rem .9rem;background:var(--bg);\
white-space:nowrap}\
td{padding:.55rem .9rem;border-top:1px solid var(--line);vertical-align:top}\
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em}\
pre{background:var(--code);color:var(--codefg);padding:.9rem 1rem;border-radius:6px;\
overflow-x:auto;margin:0 0 .8rem;font-size:.82rem;line-height:1.6}\
.pill{display:inline-block;font:500 .72rem/1.5 ui-monospace,Menlo,monospace;padding:.1rem .45rem;\
border-radius:3px;white-space:nowrap}\
.ok{background:var(--okbg);color:var(--ok)}.wn{background:var(--warnbg);color:var(--warn)}\
.dn{background:var(--denybg);color:var(--deny)}\
.eyebrow{font:500 .7rem/1.4 ui-monospace,Menlo,monospace;letter-spacing:.12em;\
text-transform:uppercase;color:var(--faint);margin:0 0 .8rem}\
.grid{display:flex;flex-wrap:wrap;gap:.75rem;margin:0 0 1.2rem}\
.stat{flex:1 1 8rem;background:var(--card);border:1px solid var(--line);border-radius:6px;\
padding:.7rem .9rem}\
.stat b{display:block;font:600 1.5rem/1.2 ui-serif,Georgia,serif}\
.stat span{font-size:.78rem;color:var(--faint)}\
label{display:block;font-size:.8rem;color:var(--soft);margin:.6rem 0 .2rem}\
select,input{font:inherit;font-size:.9rem;padding:.4rem .5rem;background:var(--bg);\
color:var(--ink);border:1px solid var(--line);border-radius:4px;max-width:100%}\
a{color:var(--accent)}a:focus-visible,select:focus-visible{outline:2px solid var(--accent);\
outline-offset:2px}\
.none{color:var(--faint);font-size:.9rem}";

/// Render the whole page.
#[must_use]
pub fn render(v: &View<'_>) -> String {
    let mut h = String::with_capacity(16 * 1024);
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str("<title>warden-connect</title><style>");
    h.push_str(CSS);
    h.push_str("</style></head><body><div class=\"wrap\">");

    h.push_str("<p class=\"eyebrow\">warden-connect &middot; read-only</p>");
    h.push_str("<h1>Connections</h1>");
    h.push_str(&format!("<p class=\"sub\">{}</p>", esc(v.iss)));

    // --- the numbers, worst-first in meaning rather than in size ---
    let unattested = v
        .entities
        .iter()
        .filter(|e| e.posture == Posture::Unattested)
        .count();
    let shadow = shadow_rows(v).len();
    h.push_str("<div class=\"grid\">");
    stat(&mut h, &v.contracts.to_string(), "live contracts");
    stat(&mut h, &v.pending.len().to_string(), "awaiting a decision");
    stat(&mut h, &shadow.to_string(), "unregistered servers");
    stat(&mut h, &unattested.to_string(), "unattested parties");
    h.push_str("</div>");

    shadow_section(&mut h, v);
    catalogue_section(&mut h, v);
    generator_section(&mut h, v);
    pending_section(&mut h, v);
    impact_section(&mut h, v);
    evidence_section(&mut h, v);

    h.push_str("<h2>Why there are no buttons here</h2>");
    h.push_str(
        "<p class=\"lede\">Every change is a reviewed merge in a repository somebody owns. A button \
         that minted or approved would be a second consent path for the same decision, with an \
         authorization model of its own to decide who may press it. This page explains; the CLI \
         executes; the merge is the approval.</p>",
    );

    h.push_str("</div></body></html>");
    h
}

fn stat(h: &mut String, value: &str, label: &str) {
    h.push_str(&format!(
        "<div class=\"stat\"><b>{}</b><span>{}</span></div>",
        esc(value),
        esc(label)
    ));
}

/// Scanned servers that no registered entity accounts for.
///
/// The comparison is by **target** — the command line or URL a client was configured with — not by
/// the name a team gave it. A local label is a local decision; two teams calling the same server
/// different things is one server.
fn shadow_rows<'a>(v: &'a View<'a>) -> Vec<(&'a str, usize, bool)> {
    let Some(inv) = v.inventory else {
        return Vec::new();
    };
    let mut rows: Vec<(&str, usize, bool)> = inv
        .by_server()
        .into_iter()
        .map(|(target, decls)| {
            let known = v.known_targets.contains_key(target);
            (target, decls.len(), known)
        })
        .filter(|(_, _, known)| !known)
        .collect();
    // Most-used first: a server eleven repositories depend on is a different conversation from one
    // with a single caller.
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows
}

fn shadow_section(h: &mut String, v: &View<'_>) {
    h.push_str("<h2>Used, but not registered</h2>");
    if let Some(why) = &v.inventory_error {
        h.push_str(&format!(
            "<div class=\"card\"><span class=\"pill dn\">sweep unreadable</span> \
             <p class=\"lede\">A discovery sweep <em>was</em> configured and could not be read, so \
             this section is blank for a reason that is not \"nothing was found\": \
             <code>{}</code></p></div>",
            esc(why)
        ));
        return;
    }
    let Some(inv) = v.inventory else {
        h.push_str(
            "<p class=\"lede\">No discovery sweep has been supplied. Run <code>connect inventory \
             --org ORG --shim CMD --out inventory.json</code> and start <code>serve</code> with \
             <code>--inventory inventory.json</code>.</p>",
        );
        return;
    };
    let rows = shadow_rows(v);
    h.push_str(&format!(
        "<p class=\"lede\">{} repositories scanned, {} declarations found. Nothing was probed — \
         these come from reading client configuration, not from asking any server what it can \
         do.</p>",
        inv.repos_scanned,
        inv.findings.len()
    ));
    if rows.is_empty() {
        h.push_str("<p class=\"none\">Every scanned server is registered.</p>");
        return;
    }
    h.push_str("<div class=\"tw\"><table><tr><th>Target</th><th>Callers</th><th>Status</th></tr>");
    for (target, callers, _) in &rows {
        h.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td>\
             <td><span class=\"pill dn\">unregistered</span></td></tr>",
            esc(target),
            callers
        ));
    }
    h.push_str("</table></div>");
    h.push_str(
        "<p class=\"lede\">To bring one under management: <code>connect inventory promote --from \
         inventory.json --target '&lt;target&gt;' --owner human:&lt;who&gt; --zone \
         internal.&lt;zone&gt;</code></p>",
    );
}

fn catalogue_section(h: &mut String, v: &View<'_>) {
    h.push_str("<h2>Catalogue</h2>");
    let Some(me) = v.as_consumer else {
        h.push_str(
            "<p class=\"lede\">A catalogue is always <em>somebody's</em>. Every row is something a \
             provider agreed to expose to that consumer's audience, so there is no unfiltered \
             view.</p>",
        );
        h.push_str("<div class=\"card\"><label for=\"pick\">Show the catalogue for</label>");
        h.push_str("<select id=\"pick\" onchange=\"if(this.value)location.search='?as='+encodeURIComponent(this.value)\">");
        h.push_str("<option value=\"\">choose a consumer&hellip;</option>");
        for e in &v.entities {
            if e.lifecycle == Lifecycle::Active {
                h.push_str(&format!(
                    "<option value=\"{}\">{}</option>",
                    esc(e.id.as_str()),
                    esc(e.id.as_str())
                ));
            }
        }
        h.push_str("</select></div>");
        return;
    };
    h.push_str(&format!(
        "<p class=\"lede\">As <code>{}</code> &mdash; zone <code>{}</code>, tier {}.</p>",
        esc(me.id.as_str()),
        esc(me.zone.as_str()),
        me.tier.as_u8()
    ));
    if v.catalogue.is_empty() {
        h.push_str(
            "<p class=\"none\">Nothing is offered to this zone and tier. That is an answer, not an \
             error &mdash; no provider has published terms covering it.</p>",
        );
        return;
    }
    h.push_str(
        "<div class=\"tw\"><table><tr><th>Provider</th><th>Now</th><th>On ask</th>\
         <th>Consent</th></tr>",
    );
    for c in &v.catalogue {
        h.push_str(&format!(
            "<tr><td class=\"mono\">{}<br><span class=\"none\">v{}</span></td>\
             <td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            esc(c.asset.as_str()),
            c.version,
            if c.pre_granted.is_empty() {
                "&mdash;".to_string()
            } else {
                esc(&c.pre_granted.join(", "))
            },
            if c.needs_approval.is_empty() {
                "&mdash;".to_string()
            } else {
                esc(&c.needs_approval.join(", "))
            },
            if c.consented {
                "<span class=\"pill ok\">verified merge</span>"
            } else {
                // Functional, not advisory: `need apply` refuses an offer with no verified
                // publishing merge, so a row without it cannot be contracted at all.
                "<span class=\"pill wn\">unsigned &mdash; cannot be contracted</span>"
            }
        ));
    }
    h.push_str("</table></div>");
    h.push_str(
        "<p class=\"lede\"><b>Now</b> is contractable today; the offer itself is the provider's \
         consent. <b>On ask</b> is offered to you and decided per consumer by the provider's \
         registered owner.</p>",
    );
}

/// The command generator — the point of the whole page.
///
/// Operates on data already in the document. No fetches, no writes, and nothing to authorise: it
/// assembles text you paste into a terminal, where the existing approval path takes over.
fn generator_section(h: &mut String, v: &View<'_>) {
    let Some(me) = v.as_consumer else { return };
    if v.catalogue.is_empty() {
        return;
    }
    h.push_str("<h2>What to run</h2>");
    h.push_str(
        "<p class=\"lede\">Pick a provider and the tools you need. This writes the manifest and the \
         command; the pull request is where it gets approved.</p>",
    );

    // Embedded as JSON in a script tag, not built into JS string literals. `</script>` inside a
    // value would otherwise end the block early, which is the classic way this goes wrong.
    let data: Vec<serde_json::Value> = v
        .catalogue
        .iter()
        .map(|c| {
            serde_json::json!({
                "asset": c.asset.as_str(),
                "now": c.pre_granted,
                "ask": c.needs_approval,
            })
        })
        .collect();
    let json = serde_json::to_string(&serde_json::json!({
        "consumer": me.id.as_str(),
        "needs_path": NEEDS_PATH,
        "offers": data,
    }))
    .unwrap_or_else(|_| "{}".to_string())
    .replace("</", "<\\/");

    h.push_str("<div class=\"card\">");
    h.push_str("<label for=\"prov\">Provider</label><select id=\"prov\"></select>");
    h.push_str("<label for=\"tools\">Tools (ctrl-click for more than one)</label>");
    h.push_str("<select id=\"tools\" multiple size=\"5\"></select>");
    h.push_str("<label for=\"ttl\">Lifetime, seconds</label>");
    h.push_str("<input id=\"ttl\" type=\"number\" value=\"3600\" min=\"60\">");
    h.push_str("<label for=\"why\">Justification &mdash; a reviewer reads this</label>");
    h.push_str(
        "<input id=\"why\" size=\"48\" value=\"\" placeholder=\"why this connection is needed\">",
    );
    h.push_str("</div>");
    h.push_str("<p class=\"eyebrow\">1 &middot; commit this</p><pre id=\"manifest\"></pre>");
    h.push_str(
        "<p class=\"eyebrow\">2 &middot; after it is reviewed and merged</p><pre id=\"cmd\"></pre>",
    );

    h.push_str("<script type=\"application/json\" id=\"wc\">");
    h.push_str(&json);
    h.push_str("</script><script>(function(){");
    h.push_str("var D=JSON.parse(document.getElementById('wc').textContent);");
    h.push_str("var P=document.getElementById('prov'),T=document.getElementById('tools');");
    h.push_str("var M=document.getElementById('manifest'),C=document.getElementById('cmd');");
    h.push_str("var TT=document.getElementById('ttl'),W=document.getElementById('why');");
    h.push_str("D.offers.forEach(function(o,i){var x=document.createElement('option');");
    h.push_str("x.value=i;x.textContent=o.asset;P.appendChild(x)});");
    h.push_str("function tools(){T.innerHTML='';var o=D.offers[P.value];if(!o)return;");
    h.push_str("o.now.concat(o.ask).forEach(function(t){var x=document.createElement('option');");
    h.push_str(
        "x.value=t;x.textContent=t+(o.ask.indexOf(t)>=0?'  (needs the owner to approve)':'');",
    );
    h.push_str("T.appendChild(x)})}");
    h.push_str(
        "function draw(){var o=D.offers[P.value];if(!o){M.textContent='';C.textContent='';return}",
    );
    h.push_str("var sel=[].slice.call(T.selectedOptions).map(function(x){return x.value});");
    h.push_str("var q=function(s){return '\"'+String(s).replace(/\\\\/g,'\\\\\\\\').replace(/\"/g,'\\\\\"')+'\"'};");
    h.push_str("var ttl=parseInt(TT.value,10)||3600;");
    h.push_str("var why=W.value||'describe why this connection is needed';");
    h.push_str(
        "M.textContent='# '+D.needs_path+'\\n'+'asset = '+q(D.consumer)+'\\n\\n[[need]]\\n'",
    );
    h.push_str("+'to = '+q(o.asset)+'\\n'+'tools = ['+sel.map(q).join(', ')+']\\n'");
    h.push_str("+'justify = '+q(why)+'\\n'+'ttl = '+ttl+'\\n';");
    h.push_str("C.textContent='connect need check\\n\\n# then, after the merge:\\n'");
    h.push_str(
        "+'connect need apply \\\\\\n  --repo <your-repo> --sha $(git rev-parse HEAD) \\\\\\n'",
    );
    h.push_str("+'  --mediator <mediator-id> \\\\\\n  --shim \"$SHIM\" --shim-label gh \\\\\\n'");
    h.push_str("+'  --issuer-key issuer.pem --kid k1';}");
    h.push_str("P.addEventListener('change',function(){tools();draw()});");
    h.push_str("[T,TT,W].forEach(function(e){e.addEventListener('input',draw)});");
    h.push_str("tools();draw();})();</script>");
}

/// One connection, and the trail behind it.
///
/// The question an audit asks: *show me why this connection exists.* Answerable today only by
/// somebody who can run `connect show` and read a chain file — so it is answerable by the platform
/// team and by nobody else, which is the wrong shape for evidence.
///
/// Rows come from the evidence chain, filtered by `cid`, which is the correlation root stamped on
/// every action for exactly this purpose.
fn evidence_section(h: &mut String, v: &View<'_>) {
    h.push_str("<h2>Why does this connection exist</h2>");
    let Some((cid, record, rows)) = &v.lookup else {
        h.push_str(
            "<p class=\"lede\">Add <code>?cid=conn_…</code> to see one connection: what it grants, \
             who approved it, and every recorded action behind it.</p>",
        );
        return;
    };
    let Some(rec) = record else {
        // Not the same as a connection with no trail. One means you asked about something that does
        // not exist; the other would mean the register holds a contract nothing recorded.
        h.push_str(&format!(
            "<div class=\"card\"><span class=\"pill dn\">no such connection</span> \
             <p class=\"lede\">Nothing in the register has the id <code>{}</code>. That is \
             different from a connection with no evidence, which would be alarming.</p></div>",
            esc(cid)
        ));
        return;
    };

    h.push_str(&format!(
        "<div class=\"card\"><p class=\"lede\"><code>{}</code> &rarr; <code>{}</code><br>\
         grants <code>{}</code><br>expires {} &middot; policy <code>{}</code></p></div>",
        esc(rec.caller.as_str()),
        esc(rec.callee.as_str()),
        esc(&rec.surface.items().join(", ")),
        esc(&crate::export::iso8601(rec.exp)),
        esc(&rec.policy_version)
    ));

    // The consent, and where it happened. A merge pointer is more useful than the approval record
    // itself: it is where somebody can go and read what was agreed.
    h.push_str("<div class=\"tw\"><table><tr><th>Consent</th><th>Detail</th></tr>");
    h.push_str(&format!(
        "<tr><td>mode</td><td class=\"mono\">{:?}</td></tr>",
        rec.approval.mode
    ));
    if let Some(by) = &rec.approval.by {
        h.push_str(&format!(
            "<tr><td>approved by</td><td class=\"mono\">{}</td></tr>",
            esc(by.as_str())
        ));
    }
    if let Some(second) = &rec.approval.second {
        h.push_str(&format!(
            "<tr><td>second approver</td><td class=\"mono\">{}</td></tr>",
            esc(second.as_str())
        ));
    }
    for m in &rec.approval.merges {
        h.push_str(&format!(
            "<tr><td>merge ({:?})</td><td class=\"mono\">{}@{}<br>request {} &middot; author {} \
             &middot; approved by {}</td></tr>",
            m.side,
            esc(&m.repo),
            esc(&m.sha),
            esc(&m.request_id),
            esc(&m.author),
            esc(&m.approvers.join(", "))
        ));
    }
    h.push_str("</table></div>");

    if rows.is_empty() {
        // Worth saying loudly. A contract in the register with nothing recorded behind it is either
        // a chain that was truncated or a mint that skipped its own evidence write.
        h.push_str(
            "<div class=\"card\"><span class=\"pill dn\">no evidence rows</span> \
             <p class=\"lede\">This connection is in the register and the chain has nothing for \
             it. That should not happen: either the chain was truncated, or something minted \
             without recording it. Run <code>connect audit verify --anchor-pub</code>.</p></div>",
        );
        return;
    }
    h.push_str(
        "<div class=\"tw\"><table><tr><th>Seq</th><th>When</th><th>Event</th><th>Actor</th>\
         <th>Decision</th><th>Why</th></tr>",
    );
    for e in rows {
        let pill = match e.decision.as_str() {
            "deny" => "dn",
            "hold" => "wn",
            _ => "ok",
        };
        h.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td>\
             <td class=\"mono\">{}</td><td><span class=\"pill {pill}\">{}</span></td>\
             <td>{}</td></tr>",
            e.seq,
            esc(&crate::export::iso8601(e.ts)),
            esc(&e.kind),
            esc(&e.actor),
            esc(&e.decision),
            esc(&e.reason)
        ));
    }
    h.push_str("</table></div>");
    h.push_str(&format!(
        "<p class=\"lede\">{} row(s), oldest first. This page shows the chain's contents, not its \
         integrity — whether it has been tampered with is what <code>connect audit verify \
         --anchor-pub</code> answers, and no page can answer it by displaying itself.</p>",
        rows.len()
    ));
}

/// What a provider needs before removing anything.
///
/// The provider-facing half of the page. `offer status` answers this on a terminal; a provider
/// deciding whether to withdraw a tool wants to see the consumers, not parse a report.
///
/// Four buckets, and they are separate because the actions differ. `gone` means the provider's
/// intent and a live contract have diverged with no path back. `on ask` means the provider chose to
/// decide each consumer and there is a person who can restore it — themselves. Conflating those
/// two sends a provider to fix a term that is behaving exactly as they configured it.
fn impact_section(h: &mut String, v: &View<'_>) {
    let affected: usize = v.impacts.iter().map(|(_, i)| i.affected.len()).sum();
    h.push_str("<h2>Who breaks if you remove something</h2>");
    if v.impacts.is_empty() {
        h.push_str(
            "<p class=\"lede\">No offers are held, so there is nothing to withdraw yet.</p>",
        );
        return;
    }
    if affected == 0 {
        h.push_str(
            "<p class=\"lede\">Every live contract sits inside the terms now in force. Nothing to \
             report — which is the answer a provider wants before a change, not after one.</p>",
        );
        return;
    }
    h.push_str(
        "<div class=\"tw\"><table><tr><th>Provider</th><th>Connection</th><th>Consumer</th>\
         <th>What</th><th>Expires</th></tr>",
    );
    for (asset, imp) in &v.impacts {
        for a in &imp.affected {
            let (pill, what) = if !a.gone.is_empty() {
                ("dn", format!("gone: {}", a.gone.join(", ")))
            } else if !a.withdrawn.is_empty() {
                (
                    "dn",
                    format!(
                        "past its date: {}",
                        a.withdrawn
                            .iter()
                            .map(|(i, _)| i.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            } else if !a.needs_approval.is_empty() {
                ("wn", format!("on ask: {}", a.needs_approval.join(", ")))
            } else {
                (
                    "wn",
                    format!(
                        "scheduled: {}",
                        a.withdrawing
                            .iter()
                            .map(|(i, _)| i.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            };
            h.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td>\
                 <td class=\"mono\">{}</td><td><span class=\"pill {pill}\">{}</span></td>\
                 <td class=\"mono\">{}</td></tr>",
                esc(asset.as_str()),
                esc(&a.cid),
                esc(a.consumer.as_str()),
                esc(&what),
                esc(&crate::export::iso8601(a.exp))
            ));
        }
    }
    h.push_str("</table></div>");
    h.push_str(
        "<p class=\"lede\">A version bump changes nothing about a contract already issued — it is a \
         signed ceiling with a hard expiry, and letting a publisher shorten one remotely would make \
         the artifact a cache of a mutable decision. What closes the gap is the contract's own \
         expiry, the consumer's next build, and — if the tool really goes — surface drift at the \
         mediator, which fails closed with nobody publishing anything.</p>",
    );
}

fn pending_section(h: &mut String, v: &View<'_>) {
    h.push_str("<h2>Awaiting a decision</h2>");
    if v.pending.is_empty() {
        h.push_str("<p class=\"none\">Nothing is waiting.</p>");
        return;
    }
    h.push_str(
        "<div class=\"tw\"><table><tr><th>Request</th><th>Connection</th><th>Items</th>\
         <th>Waiting on</th></tr>",
    );
    for (r, callee) in &v.pending {
        let waiting = match callee {
            // The registered owner, read from the registry — the same source the approval check
            // uses, so this page cannot show a different name from the one that will be enforced.
            Some(e) if r.owner_must_approve => format!("{} (owner)", e.owner.as_str()),
            _ => r
                .approver_role
                .clone()
                .map_or_else(|| "an approver".to_string(), |role| format!("role {role}")),
        };
        h.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}<br>&rarr; {}</td>\
             <td class=\"mono\">{}</td><td>{}</td></tr>",
            esc(&r.id),
            esc(r.caller.as_str()),
            esc(r.callee.as_str()),
            esc(&r.surface.items().join(", ")),
            esc(&waiting)
        ));
    }
    h.push_str("</table></div>");
    h.push_str(&format!(
        "<p class=\"lede\">A provider settles one with <code>connect approve &lt;req&gt; --emit \
         &lt;dir&gt;</code>, then a reviewed merge of that file. Requests lapse on their own; \
         {} shown.</p>",
        v.pending.len()
    ));
}

/// Requests still open, newest first, with the callee attached.
#[must_use]
pub fn open_requests<'a>(
    requests: &'a std::collections::HashMap<String, PendingRequest>,
    entity: impl Fn(&EntityId) -> Option<&'a Entity>,
    now: u64,
) -> Vec<(&'a PendingRequest, Option<&'a Entity>)> {
    let mut out: Vec<&PendingRequest> = requests
        .values()
        .filter(|r| r.status == RequestStatus::Pending && !r.has_lapsed(now))
        .collect();
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
    out.into_iter().map(|r| (r, entity(&r.callee))).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn entity(id: &str, zone: &str) -> Entity {
        Entity::pending(
            EntityId::new(id).unwrap(),
            wc_core::model::Kind::Agent,
            wc_core::model::HumanRef::new("human:owner@bank").unwrap(),
            wc_core::model::ZoneId::new(zone).unwrap(),
            wc_core::model::Tier::TWO,
            1_000,
        )
    }

    fn view<'a>(me: Option<&'a Entity>, cat: Vec<CatalogueEntry>) -> View<'a> {
        View {
            as_consumer: me,
            catalogue: cat,
            entities: Vec::new(),
            pending: Vec::new(),
            inventory: None,
            inventory_error: None,
            known_targets: BTreeMap::new(),
            impacts: Vec::new(),
            lookup: None,
            contracts: 0,
            iss: "https://connect.internal",
        }
    }

    fn cat_entry(items_now: &[&str], on_ask: &[&str], consented: bool) -> CatalogueEntry {
        CatalogueEntry {
            asset: EntityId::new("urn:acme:mcp:pay").unwrap(),
            version: 1,
            surface_kind: wc_core::canon::SurfaceKind::McpTools,
            surface_digest: "sha256:aa".to_string(),
            pre_granted: items_now.iter().map(|s| (*s).to_string()).collect(),
            needs_approval: on_ask.iter().map(|s| (*s).to_string()).collect(),
            withdrawing: Vec::new(),
            consented,
        }
    }

    #[test]
    fn the_page_never_offers_a_way_to_write() {
        // The design claim, asserted rather than trusted. A form or a button here would be a second
        // consent path for a decision that already has one, with its own authorization model.
        let me = entity("urn:acme:repo:recon", "internal.a");
        let html = render(&view(
            Some(&me),
            vec![cat_entry(&["get_balance"], &["transfer_funds"], true)],
        ));
        assert!(!html.contains("<form"), "a form appeared");
        assert!(!html.contains("<button"), "a button appeared");
        assert!(
            !html.to_lowercase().contains("method=\"post\""),
            "a POST appeared"
        );
        // `form-action 'none'` is on the response header; this is the document half of the same
        // claim, so a future edit has to defeat both.
        assert!(html.contains("Why there are no buttons"));
    }

    #[test]
    fn an_unreadable_sweep_does_not_render_as_an_empty_one() {
        // "I looked and could not" must never read the same as "there was nothing to look at". The
        // first version of this page swallowed the parse error and rendered the no-sweep message,
        // which sends an operator to check a flag they had already passed.
        let mut v = view(None, Vec::new());
        v.inventory_error = Some("inventory.json is not an inventory: expected value".to_string());
        let html = render(&v);
        assert!(html.contains("sweep unreadable"), "{html}");
        assert!(
            !html.contains("No discovery sweep has been supplied"),
            "the two cases rendered the same"
        );
    }

    #[test]
    fn an_unsigned_offer_says_it_cannot_be_contracted() {
        // Functional, not advisory: `need apply` refuses an offer whose publishing merge was never
        // verified, so a catalogue that hid this would advertise items that fail at the last step.
        let me = entity("urn:acme:repo:recon", "internal.a");
        let signed = render(&view(
            Some(&me),
            vec![cat_entry(&["get_balance"], &[], true)],
        ));
        assert!(signed.contains("verified merge"), "{signed}");
        let unsigned = render(&view(
            Some(&me),
            vec![cat_entry(&["get_balance"], &[], false)],
        ));
        assert!(unsigned.contains("cannot be contracted"), "{unsigned}");
    }

    #[test]
    fn there_is_no_unfiltered_catalogue() {
        // Without a named consumer the page must show a picker, never rows. A catalogue is always
        // somebody's — an unfiltered one is the enumerable directory `discover` refuses to publish.
        //
        // Entities AND rows are supplied on purpose. The first version passed both empty, so a
        // mutation that fell back to "the first registered entity" changed nothing and the test
        // still passed — it was asserting against an absence it had created itself.
        let other = entity("urn:acme:repo:someone-else", "internal.a");
        let mut v = view(
            None,
            vec![cat_entry(&["get_balance"], &["transfer_funds"], true)],
        );
        v.entities = vec![&other];
        let html = render(&v);
        assert!(
            html.contains("A catalogue is always"),
            "no explanation of why"
        );
        assert!(html.contains("choose a consumer"), "no picker");
        assert!(
            !html.contains("verified merge"),
            "catalogue rows rendered with no consumer named"
        );
        assert!(
            !html.contains("What to run"),
            "the generator rendered with no consumer named"
        );
    }

    #[test]
    fn a_tool_name_cannot_break_out_of_the_embedded_json() {
        // The generator embeds the catalogue as JSON in a script tag. A tool name containing
        // `</script>` would end the block early and the rest of the page would render as markup.
        let me = entity("urn:acme:repo:recon", "internal.a");
        let html = render(&view(
            Some(&me),
            vec![cat_entry(
                &["</script><img src=x onerror=alert(1)>"],
                &[],
                true,
            )],
        ));
        assert!(
            !html.contains("</script><img"),
            "the payload survived into the document"
        );
        assert!(
            html.contains(r"<\/script>"),
            "the escape did not happen: {html}"
        );
    }

    #[test]
    fn an_unknown_cid_is_not_the_same_as_a_connection_with_no_trail() {
        // Two answers a lookup must not merge. "You asked about something that does not exist" is
        // ordinary; "the register holds a contract and the chain has nothing for it" means the chain
        // was truncated or a mint skipped its own evidence write, and only one of those is alarming.
        let mut v = view(None, Vec::new());
        v.lookup = Some(("conn_deadbeef".to_string(), None, Vec::new()));
        let html = render(&v);
        assert!(html.contains("no such connection"), "{html}");
        assert!(
            !html.contains("no evidence rows"),
            "an unknown cid must not read as a missing trail"
        );
    }

    #[test]
    fn a_known_cid_with_an_empty_chain_says_so_loudly() {
        let rec = contract_record();
        let mut v = view(None, Vec::new());
        v.lookup = Some(("conn_abcdef12".to_string(), Some(&rec), Vec::new()));
        let html = render(&v);
        assert!(html.contains("no evidence rows"), "{html}");
        assert!(html.contains("audit verify"), "it must say what to run");
        assert!(!html.contains("no such connection"), "the record exists");
    }

    #[test]
    fn a_lookup_names_the_merge_the_consent_came_from() {
        // The point of the view. An auditor wants the pull request, not a rendering of the approval
        // record — the merge is where they can go and read what was agreed.
        let rec = contract_record();
        let rows = [chain_entry(1, "contract.mint", "allow", "minted")];
        let refs: Vec<&chain::Entry> = rows.iter().collect();
        let mut v = view(None, Vec::new());
        v.lookup = Some(("conn_abcdef12".to_string(), Some(&rec), refs));
        let html = render(&v);
        assert!(html.contains("bank/payments-mcp"), "no merge repo: {html}");
        assert!(html.contains("request 412"), "no request id");
        assert!(html.contains("contract.mint"), "no evidence row");
        // The page shows contents, not integrity. Claiming otherwise would be the worst possible
        // thing for it to imply.
        assert!(
            html.contains("not its integrity"),
            "the page must not imply it verified the chain"
        );
    }

    fn contract_record() -> ContractRecord {
        use wc_core::contract::{ApprovalMode, ApprovalRef, MergeApproval, Side, Surface, Terms};
        ContractRecord {
            cid: wc_core::model::Cid::new("conn_abcdef12").unwrap(),
            jti: wc_core::model::Jti::new("cx_abcdef1234567890").unwrap(),
            caller: EntityId::new("urn:acme:repo:recon").unwrap(),
            callee: EntityId::new("urn:acme:mcp:pay").unwrap(),
            caller_zone: wc_core::model::ZoneId::new("internal.apac").unwrap(),
            callee_zone: wc_core::model::ZoneId::new("internal.payments").unwrap(),
            callee_tier: wc_core::model::Tier::TWO,
            callee_manifest: "sha256:m1".to_string(),
            surface_digest: "sha256:sd".to_string(),
            surface: Surface {
                tools: vec!["get_balance".to_string()],
                skills: Vec::new(),
                resources: Vec::new(),
            },
            terms: Terms::default(),
            aud: vec!["m:1".to_string()],
            jws_sha256: "sha256:j".to_string(),
            status: wc_core::contract::ContractStatus::Active,
            approval: ApprovalRef {
                by: Some(wc_core::model::HumanRef::new("human:owner@bank").unwrap()),
                jti: None,
                ticket: None,
                mode: ApprovalMode::Human,
                second: None,
                merges: vec![MergeApproval {
                    side: Side::Target,
                    repo: "bank/payments-mcp".to_string(),
                    sha: "abc".to_string(),
                    request_id: "412".to_string(),
                    author: "dev@bank".to_string(),
                    approvers: vec!["owner@bank".to_string()],
                    via: "gh".to_string(),
                }],
            },
            policy_version: "live@v1".to_string(),
            iat: 1_787_000_000,
            exp: 1_787_003_600,
            offer_version: Some(1),
            schema: 1,
        }
    }

    fn chain_entry(seq: u64, kind: &str, decision: &str, reason: &str) -> chain::Entry {
        chain::Entry {
            seq,
            ts: 1_787_000_000,
            kind: kind.to_string(),
            cid: Some("conn_abcdef12".to_string()),
            contract_jti: None,
            entities: Vec::new(),
            actor: "human:me@x".to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
            policy_version: "live@v1".to_string(),
            detail: serde_json::Value::Null,
            prev_hash: String::new(),
            row_hash: String::new(),
            schema: 1,
        }
    }

    #[test]
    fn gone_and_on_ask_are_told_apart_in_the_blast_radius() {
        // The distinction a provider acts on. `gone` means their intent and a live contract have
        // diverged with no path back; `on ask` means they chose to decide each consumer and can
        // restore it themselves. Conflating them sends a provider to fix a working term.
        use crate::offer::{Affected, Impact};
        let mut v = view(None, Vec::new());
        v.impacts = vec![(
            EntityId::new("urn:acme:mcp:pay").unwrap(),
            Impact {
                version: 2,
                live: 2,
                behind: 1,
                affected: vec![
                    Affected {
                        cid: "conn_11111111".to_string(),
                        consumer: EntityId::new("urn:acme:repo:a").unwrap(),
                        minted_under: Some(1),
                        exp: 1_787_000_000,
                        gone: vec!["removed_tool".to_string()],
                        needs_approval: Vec::new(),
                        withdrawn: Vec::new(),
                        withdrawing: Vec::new(),
                    },
                    Affected {
                        cid: "conn_22222222".to_string(),
                        consumer: EntityId::new("urn:acme:repo:b").unwrap(),
                        minted_under: Some(1),
                        exp: 1_787_000_000,
                        gone: Vec::new(),
                        needs_approval: vec!["transfer_funds".to_string()],
                        withdrawn: Vec::new(),
                        withdrawing: Vec::new(),
                    },
                ],
            },
        )];
        let html = render(&v);
        assert!(html.contains("gone: removed_tool"), "{html}");
        assert!(html.contains("on ask: transfer_funds"), "{html}");
        // Different severities, so a provider can see which row is a break and which is a decision.
        assert!(
            html.contains("pill dn\">gone"),
            "gone must read as the worse one"
        );
        assert!(
            html.contains("pill wn\">on ask"),
            "on ask must not read as a break"
        );
    }

    #[test]
    fn a_clean_estate_says_so_rather_than_showing_an_empty_table() {
        // "Nothing to report" is the answer a provider wants BEFORE a change. An empty table reads
        // as a page that failed to load.
        use crate::offer::Impact;
        let mut v = view(None, Vec::new());
        v.impacts = vec![(
            EntityId::new("urn:acme:mcp:pay").unwrap(),
            Impact {
                version: 1,
                live: 3,
                behind: 0,
                affected: Vec::new(),
            },
        )];
        let html = render(&v);
        assert!(
            html.contains("Every live contract sits inside the terms"),
            "{html}"
        );
    }

    #[test]
    fn every_dangerous_character_is_escaped() {
        assert_eq!(esc("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(esc("\"x\""), "&quot;x&quot;");
        assert_eq!(esc("it's"), "it&#39;s");
        assert_eq!(esc("a&b"), "a&amp;b");
        // Ampersand first, or an escape would be escaped again into `&amp;lt;`.
        assert_eq!(esc("&lt;"), "&amp;lt;");
        assert_eq!(esc("plain"), "plain");
    }

    #[test]
    fn a_script_tag_in_scanned_data_cannot_close_the_page() {
        // Tool names and targets come from a scan of somebody else's repository. Treating any of
        // them as trusted is how a page ends up executing a tool name.
        let out = esc("</script><script>alert(1)</script>");
        assert!(!out.contains("<script"), "{out}");
        assert!(!out.contains("</script"), "{out}");
    }
}

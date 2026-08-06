#!/usr/bin/env python3
"""Generate the warden-connect explainer set: one hub + ten use-case pages.

One shared shell so the set reads as a single system rather than eleven pages.
"""
import pathlib, html

OUT = pathlib.Path(__file__).parent / "explainers"
OUT.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# The shared design system
# ---------------------------------------------------------------------------
# Grounded in the world of a manual telephone exchange — the direct ancestor of
# a connection control plane: an operator who decides which pairs get connected.
# Graphite panels, brass jack plugs, cream labels, a red trunk line.

CSS = r"""
:root {
  --ground:#eceee9; --surface:#f7f8f5; --raised:#e3e6e0; --ink:#1a1e1c;
  --muted:#5f665f; --faint:#878e86; --rule:#cfd3cc;
  --brass:#8f6712; --brass-w:#f0e3c4;
  --teal:#26646e;  --teal-w:#d8e8ea;
  --alarm:#a03621; --alarm-w:#f2ded8;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,"Cascadia Mono","Roboto Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  --col:40rem; --wide:66rem;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground:#151816; --surface:#1d211e; --raised:#252a26; --ink:#e7eae5;
    --muted:#929a91; --faint:#6f776e; --rule:#2f352f;
    --brass:#d8a63e; --brass-w:#2e2617;
    --teal:#64b3bd;  --teal-w:#16292c;
    --alarm:#e0705a; --alarm-w:#2e1c17;
  }
}
:root[data-theme="dark"] {
  --ground:#151816; --surface:#1d211e; --raised:#252a26; --ink:#e7eae5;
  --muted:#929a91; --faint:#6f776e; --rule:#2f352f;
  --brass:#d8a63e; --brass-w:#2e2617; --teal:#64b3bd; --teal-w:#16292c;
  --alarm:#e0705a; --alarm-w:#2e1c17;
}
:root[data-theme="light"] {
  --ground:#eceee9; --surface:#f7f8f5; --raised:#e3e6e0; --ink:#1a1e1c;
  --muted:#5f665f; --faint:#878e86; --rule:#cfd3cc;
  --brass:#8f6712; --brass-w:#f0e3c4; --teal:#26646e; --teal-w:#d8e8ea;
  --alarm:#a03621; --alarm-w:#f2ded8;
}

.page{background:var(--ground);color:var(--ink);font-family:var(--serif);
  font-size:1.0625rem;line-height:1.65;margin:0 auto;padding:0 1.25rem 7rem;
  max-width:100%;overflow-x:hidden;-webkit-font-smoothing:antialiased}
.col{max-width:var(--col);margin-inline:auto}
.wide{max-width:var(--wide);margin-inline:auto}
.page p,.page ul,.page ol{margin:0 0 1.15rem}
.page li{margin-bottom:.45rem}
.page strong{font-weight:600}
.page a{color:var(--teal);text-decoration-thickness:1px;text-underline-offset:2px}
.page a:focus-visible,.page button:focus-visible{outline:2px solid var(--brass);outline-offset:3px}
code,.mono{font-family:var(--mono);font-size:.855em;font-variant-ligatures:none}
p code,li code,td code,.step code{background:var(--raised);border-radius:3px;padding:.08em .32em}

.eyebrow{font-family:var(--mono);font-size:.72rem;letter-spacing:.13em;
  text-transform:uppercase;color:var(--faint);margin:0 0 .6rem}
.eyebrow a{color:var(--faint);text-decoration:none;border-bottom:1px solid var(--rule)}
.eyebrow a:hover{color:var(--brass)}

.hero{padding:4.5rem 0 2.5rem}
.hero h1{font-size:clamp(2.1rem,5.4vw,3.4rem);line-height:1.04;letter-spacing:-.02em;
  font-weight:500;margin:0 0 1.3rem;text-wrap:balance}
.hero h1 .accent{color:var(--brass)}
.lede{font-size:1.2rem;line-height:1.55;color:var(--muted);margin-bottom:1.4rem}
.lede strong{color:var(--ink);font-weight:500}
.byline{font-family:var(--mono);font-size:.72rem;letter-spacing:.06em;color:var(--faint);
  border-top:1px solid var(--rule);padding-top:.85rem;display:flex;flex-wrap:wrap;gap:.3rem 1.4rem}

.band{padding:3rem 0}
.band+.band{border-top:1px solid var(--rule)}
h2{font-size:clamp(1.5rem,3.2vw,1.95rem);line-height:1.16;letter-spacing:-.014em;
  font-weight:500;margin:0 0 1.2rem;text-wrap:balance}
h3{font-family:var(--sans);font-size:.95rem;font-weight:650;margin:2rem 0 .7rem}
.num{font-family:var(--mono);font-size:.78rem;color:var(--brass);letter-spacing:.1em;
  display:block;margin-bottom:.5rem}

.kicker{font-family:var(--sans);font-size:1.02rem;line-height:1.5;font-weight:550;
  letter-spacing:-.01em;margin:1.8rem 0;padding:1.1rem 1.25rem;background:var(--surface);
  border:1px solid var(--rule);border-radius:2px}
.kicker .lbl{display:block;font-family:var(--mono);font-weight:400;font-size:.68rem;
  letter-spacing:.14em;text-transform:uppercase;color:var(--brass);margin-bottom:.5rem}
.aside{font-family:var(--sans);font-size:.875rem;line-height:1.58;color:var(--muted);
  border-left:2px solid var(--brass);padding:.1rem 0 .1rem 1rem;margin:1.6rem 0}
.aside strong{color:var(--ink)}

.cmd{font-family:var(--mono);font-size:.78rem;line-height:1.65;background:var(--surface);
  border:1px solid var(--rule);border-radius:2px;padding:.6rem .75rem;margin:0 0 1rem;
  overflow-x:auto;white-space:pre;color:var(--ink)}
.cmd .c{color:var(--faint)} .cmd .out{color:var(--teal)} .cmd .no{color:var(--alarm)}

/* staged flow */
.flow{display:grid;gap:0;margin:2.2rem 0}
.stage{display:grid;grid-template-columns:2.2rem 1fr;gap:0 .9rem;padding:1.1rem 0;
  border-top:1px solid var(--rule);align-items:start}
.stage:last-child{border-bottom:1px solid var(--rule)}
.stage-n{font-family:var(--mono);font-size:.9rem;color:var(--brass);padding-top:.15rem;
  font-variant-numeric:tabular-nums}
.stage h4{font-family:var(--sans);font-size:.98rem;font-weight:620;letter-spacing:-.012em;margin:0 0 .4rem}
.stage p{font-size:.94rem;margin:0 0 .5rem;color:var(--muted)}
.stage p strong{color:var(--ink);font-weight:550}
.who{font-family:var(--mono);font-size:.68rem;letter-spacing:.09em;text-transform:uppercase;
  display:inline-block;padding:.1rem .45rem;border-radius:999px;margin-bottom:.4rem}
.who.wc{color:var(--brass);background:var(--brass-w);border:1px solid var(--brass)}
.who.core{color:var(--teal);background:var(--teal-w);border:1px solid var(--teal)}
.who.both{color:var(--muted);background:var(--raised);border:1px solid var(--rule)}

/* two-layer strip */
.layers{display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));gap:1px;
  background:var(--rule);border:1px solid var(--rule);margin:2.2rem 0}
.layer{background:var(--ground);padding:1.3rem 1.2rem}
.layer .who{margin-bottom:.6rem}
.layer h4{font-family:var(--sans);font-size:.98rem;font-weight:620;margin:0 0 .5rem}
.layer p{font-size:.9rem;line-height:1.55;color:var(--muted);margin:0 0 .6rem}
.layer .verb{font-family:var(--mono);font-size:.73rem;color:var(--ink);display:block;
  padding-top:.5rem;border-top:1px solid var(--rule);overflow-x:auto;white-space:pre}

/* exception cards */
.excs{display:grid;gap:1rem;margin:2rem 0}
.exc{border:1px solid var(--rule);border-left:3px solid var(--alarm);background:var(--surface);
  padding:1.05rem 1.2rem;border-radius:2px}
.exc h4{font-family:var(--sans);font-size:.94rem;font-weight:620;margin:0 0 .45rem}
.exc h4 .tag{font-family:var(--mono);font-size:.7rem;color:var(--alarm);margin-right:.5rem}
.exc p{font-size:.9rem;line-height:1.55;margin:0;color:var(--muted)}
.exc p strong{color:var(--ink)}

/* tables */
.tw{overflow-x:auto;margin:1.8rem 0;border:1px solid var(--rule)}
table{border-collapse:collapse;width:100%;font-family:var(--sans);font-size:.85rem;min-width:34rem}
th,td{text-align:left;padding:.62rem .8rem;border-bottom:1px solid var(--rule);vertical-align:top;line-height:1.45}
th{font-family:var(--mono);font-size:.67rem;letter-spacing:.1em;text-transform:uppercase;
  color:var(--faint);font-weight:400;background:var(--surface)}
tr:last-child td{border-bottom:0}

/* evidence chips */
.chips{display:flex;flex-wrap:wrap;gap:.4rem .5rem;margin:1.2rem 0;font-family:var(--sans);font-size:.8rem}
.chip{border:1px solid var(--rule);border-radius:999px;padding:.18rem .65rem;color:var(--muted);background:var(--surface)}
.chip.ev{border-color:var(--teal);color:var(--teal);background:var(--teal-w)}
.chip.th{border-color:var(--alarm);color:var(--alarm);background:var(--alarm-w)}

/* use-case index cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(17rem,1fr));gap:1px;
  background:var(--rule);border:1px solid var(--rule);margin:2.2rem 0}
.card{background:var(--ground);padding:1.25rem 1.15rem;text-decoration:none;color:inherit;display:block}
.card:hover{background:var(--surface)}
.card .id{font-family:var(--mono);font-size:.7rem;letter-spacing:.1em;color:var(--brass);display:block;margin-bottom:.4rem}
.card h4{font-family:var(--sans);font-size:.97rem;font-weight:620;margin:0 0 .45rem;letter-spacing:-.01em}
.card p{font-size:.875rem;line-height:1.5;color:var(--muted);margin:0}
.card .go{font-family:var(--mono);font-size:.72rem;color:var(--teal);display:block;margin-top:.7rem}

/* nav */
.nav{display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between;
  border-top:1px solid var(--rule);padding-top:1.4rem;margin-top:3rem;
  font-family:var(--mono);font-size:.75rem}
.nav a{color:var(--teal);text-decoration:none}
.nav a:hover{text-decoration:underline}

.rise{opacity:0;transform:translateY(10px);transition:opacity .55s ease,transform .55s cubic-bezier(.2,.7,.3,1)}
.rise.in{opacity:1;transform:none}
@media (prefers-reduced-motion:reduce){.rise{opacity:1;transform:none;transition:none}}
"""

SCRIPT = r"""
(function(){
  var els=document.querySelectorAll('.rise');
  if(!('IntersectionObserver' in window)||window.matchMedia('(prefers-reduced-motion: reduce)').matches){
    els.forEach(function(e){e.classList.add('in')});return;
  }
  var io=new IntersectionObserver(function(en){en.forEach(function(e){
    if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}})},
    {rootMargin:'0px 0px -8% 0px',threshold:.08});
  els.forEach(function(e,i){e.style.transitionDelay=(Math.min(i,4)*50)+'ms';io.observe(e)});
})();
"""


def shell(title, body):
    return f"<title>{html.escape(title)}</title>\n\n<style>{CSS}</style>\n\n{body}\n\n<script>{SCRIPT}</script>\n"


def stage(n, who, who_label, head, para, cmd=None):
    c = f'<div class="cmd">{cmd}</div>' if cmd else ""
    return f'''<div class="stage rise">
  <div class="stage-n">{n}</div>
  <div>
    <span class="who {who}">{who_label}</span>
    <h4>{head}</h4>
    <p>{para}</p>{c}
  </div>
</div>'''


def exc(tag, head, para):
    return f'''<div class="exc rise"><h4><span class="tag">{tag}</span>{head}</h4><p>{para}</p></div>'''


def layer(who, who_label, head, para, verb):
    return f'''<div class="layer"><span class="who {who}">{who_label}</span>
  <h4>{head}</h4><p>{para}</p><span class="verb">{verb}</span></div>'''


# ---------------------------------------------------------------------------
# Use-case content
# ---------------------------------------------------------------------------

UCS = []

UCS.append(dict(
    id="uc-01", num="UC-01", slug="register-an-agent",
    name="Register and admit an internal agent",
    favicon="🪪",
    h1='Registration is a <span class="accent">decision</span>, not a form',
    lede="An agent asking to join the estate is making a claim about itself. Admission is where that claim is either <strong>proved or recorded as unproved</strong> — and it ends with the agent holding exactly zero connections.",
    thesis="Registration is not connectivity.",
    today="A team deploys an agent. Nobody records that it exists, nobody owns it, and nothing anywhere knows what it is allowed to reach. The first time anyone asks is during an incident.",
    flow=[
        ("1", "wc", "warden-connect", "Identity", "The workload identity is verified against the trust bundle — a JWT-SVID, audience-bound and expiring. <strong>The token must authenticate the id being registered</strong>: a valid token for a different workload is a refusal, not a pass."),
        ("2", "wc", "warden-connect", "Surface acquisition", "The declared surface is fetched, not asked for. This is the one stage that fails closed in <em>every</em> mode — a record with no pin is an entity whose surface can never be shown to have changed."),
        ("3", "wc", "warden-connect", "Card signature", "A detached JWS over the canonical card, verified against the <em>operator's</em> keys. Verified against a key set the party controls, it would only prove the party signed its own claim."),
        ("4", "wc", "warden-connect", "Provenance", "DSSE → in-toto → SLSA. A pass needs all three bindings: a trusted key, a subject digest matching the artifact being admitted, and a builder in the allowlist. A valid signature over a statement about <em>some other</em> artifact proves nothing."),
        ("5", "wc", "warden-connect", "Injection screening", "Eight detectors over the declared text. This is where a poisoned skill description is caught — before any model has read it."),
        ("6", "wc", "warden-connect", "Tier derivation", "From declared data classes and capability classes. Tier 1 and 2 route to a named architect, and the reasoning is recorded: a tier nobody can explain gets argued with rather than applied."),
        ("7", "wc", "warden-connect", "Pin and record", "The card is canonicalised and hashed. The entity lands in the registry <code>Pending</code>, with a posture that reflects what was actually proved."),
    ],
    layers=[
        ("wc", "warden-connect", "Owns this entirely", "Admission is a relationship-layer question — <em>may this party exist in the estate at all, and what do we know about it?</em> Warden core has no view of it and needs none.", "connect register agent --card … --owner …"),
        ("core", "Warden core", "Not involved yet", "Core enforces actions. There are no actions to enforce: the agent holds no contracts, so there is nothing for it to call. Core enters the picture at UC-04.", "— nothing to do —"),
    ],
    excs=[
        ("A1", "Unverifiable provenance", "In <strong>observe</strong> mode the agent is admitted with <code>posture: unattested</code> and flagged. In <strong>enforce</strong> mode it is refused. The mode is a deployment property, not a per-request one — in early adoption every party is unattested, so enforce mode would admit nobody."),
        ("A2", "Screening finding", "Admission blocked, with the offending text quoted to AppSec. Only four of the eight detectors may block, and only once calibrated at precision ≥ 0.98 — a screener that blocks legitimate tools gets switched off, and a switched-off control has zero recall."),
        ("A3", "No named owner", "Refused. Ownership is enforced by the type: the owner field is not an <code>Option</code>, so an unowned entity cannot be constructed."),
        ("A4", "Re-registration with a changed card", "Treated as <strong>drift</strong>, not an update. A changed surface on a live party is UC-06, and letting a re-register overwrite the pin would be a rug-pull with a friendly name."),
    ],
    evidence=["Registration record", "Pinned card hash", "Provenance reference", "Tier rationale", "Approver, if any"],
    threats=["Rogue agents", "Spoofing", "Communication poisoning at source"],
    close="Every stage records its verdict — <em>passed</em>, <em>degraded</em>, or <em>skipped, with the reason</em>. An admission that silently omitted provenance is worse than one that says it omitted it, because nobody investigates a stage that reported nothing.",
))

UCS.append(dict(
    id="uc-02", num="UC-02", slug="onboard-a-tool-server",
    name="Onboard a tool server and pin its surface",
    favicon="📌",
    h1='A hash is the difference between <span class="accent">trusting</span> a server and <span class="accent">watching</span> one',
    lede="Onboarding a tool server means capturing exactly what it offers, canonicalising it, and hashing it. Everything later — drift detection, contract scoping, the rug-pull defence — is downstream of that one number.",
    thesis="There is no register on trust.",
    today="An MCP endpoint appears in a config file. Its tool list is whatever it says today. If a description changes tomorrow, nothing anywhere notices, and the change is invisible to every consumer.",
    flow=[
        ("1", "wc", "warden-connect", "Handshake, not questionnaire", "An MCP <code>initialize</code> plus <code>tools/list</code>, over the wire. The full declared surface is captured from the server itself rather than from a form somebody filled in."),
        ("2", "wc", "warden-connect", "Screen every field", "Names, descriptions, parameter documentation. <strong>This is where a poisoned description is caught</strong> — at onboarding, before any agent's model has read it, rather than at drift-detection time afterwards."),
        ("3", "wc", "warden-connect", "Declare the flows", "Data classes and jurisdictions. Not decoration: these become the egress terms a mediator enforces, and the columns a DORA register needs."),
        ("4", "wc", "warden-connect", "Canonicalise", "<code>wcs1</code>: a field allowlist, NFC, whitespace collapsed, keys sorted. Zero-width and bidi characters are <strong>preserved</strong> — normalisation must never launder an attack, and preserving them is exactly what makes detector S1 possible."),
        ("5", "wc", "warden-connect", "Hash, per item and whole", "A digest for the manifest and one for each tool. Per-item hashes are what make drift <em>quiet</em>: a typo in an uncontracted tool does not look like an attack on a contracted one."),
        ("6", "wc", "warden-connect", "Pin and schedule", "The pin is written and a re-attestation interval is set from the tier — one hour at tier 1, seven days at tier 4, jittered so an estate onboarded by one CI run does not re-attest in one second."),
    ],
    layers=[
        ("wc", "warden-connect", "Captures and pins the surface", "The declared surface is a relationship-layer fact: it is the <em>ceiling</em> any future contract can be cut from. Core never sees it.", "connect register server --endpoint … --surface"),
        ("core", "Warden core", "Will enforce inside it later", "Once a contract exists, core decides each <code>tools/call</code>. It has no way to know the surface moved — which is precisely why UC-06 lives here.", "— after UC-04 —"),
    ],
    excs=[
        ("A1", "A third-party server", "Additionally needs a supplier record, is admitted at <code>zone: partner</code>, and the partner bar then applies to <em>every</em> future connection: signed card mandatory, provenance mandatory, human approval, delegation depth 1."),
        ("A2", "Surface too large, or wildcard tools", "Requires an explicit scoping justification, and unbounded surfaces are refused at tier ≥ 2. A surface nobody can enumerate is a surface nobody can contract against."),
        ("A3", "Server unreachable at handshake", "Registration fails and <strong>nothing is pinned</strong>. This is the one stage that is unforgiving in both observe and enforce mode: every other check degrades, the pin cannot."),
    ],
    evidence=["Pinned manifest hash", "Per-item hashes", "CycloneDX surface BOM", "Screening report", "Supplier reference"],
    threats=["Tool poisoning", "Rug-pull (baseline established)", "Tool misuse"],
    close="The BOM is the underrated output. A tool surface <em>is</em> a dependency list — so a consumer can diff two BOMs and see exactly which tool's text changed, in the same way they would diff a lockfile.",
))

UCS.append(dict(
    id="uc-03", num="UC-03", slug="mediated-discovery",
    name="Mediated capability discovery",
    favinfo="", favicon="🔎",
    h1='A directory that answers freely hands over <span class="accent">the map</span>',
    lede="Discovery has to be the fastest way to find a capability, or the whole model collapses at step one. It is also the estate's enumeration surface — so the design question is <strong>what a caller can learn from an answer they were not entitled to</strong>.",
    thesis="Discovery hands out no reachability.",
    today="A developer asks in Slack. They get three contradictory answers, two teams point at each other, and the fastest path to working code is to skip the question entirely.",
    flow=[
        ("1", "wc", "warden-connect", "A capability question", "Not a catalogue request. <code>--capability payments.balance.read --as agent:recon</code>, and the asker must itself be registered and active: answering an unattested party would make the register a service for exactly the caller it was built to constrain."),
        ("2", "wc", "warden-connect", "Resolve candidates", "Capability keys derive from tool names, the business service and declared data classes. <strong>Descriptions are deliberately not indexed</strong> — they are attacker-controlled text, and indexing them would let a poisoned description advertise itself into other teams' searches."),
        ("3", "wc", "warden-connect", "Filter by eligibility — before shaping", "Every candidate the asker could never connect to is dropped from the result set entirely. Filtering <em>after</em> shaping would leak existence through the count."),
        ("4", "wc", "warden-connect", "Shape the answer", "Entity, capability, tier, zone, owner. No endpoint, no schema, no item list, no pin. Knowing a capability exists is not the same as being able to reach it."),
        ("5", "wc", "warden-connect", "Log the query", "Per asker, so a scanning pattern is visible as a pattern rather than as a hundred unrelated lookups."),
    ],
    layers=[
        ("wc", "warden-connect", "The whole of it", "Discovery is a relationship-layer question by definition — <em>who might I be introduced to?</em> There is no action to authorise, so core has nothing to say.", "connect discover --capability … --as …"),
        ("core", "Warden core", "Deliberately absent", "Core sees calls. A discovery query is not a call to anything, and routing it through an action-layer engine would be asking the wrong component a question it cannot answer.", "— not on this path —"),
    ],
    excs=[
        ("A1", "No eligible entries", "An empty result — and it is <strong>indistinguishable from \"exists but you may not see it\"</strong>. The test for this compares an estate where the denied entity exists against one where it does not, and asserts the answers are equal."),
        ("A2", "An enumeration pattern", "Throttled, and the throttle <em>truncates</em> rather than refusing. A status code that changes when you cross a threshold is itself a signal, and a caller who can tell \"throttled\" from \"no results\" can binary-search the estate."),
    ],
    evidence=["Discovery query log per asker", "Throttle findings"],
    threats=["Reconnaissance", "Lateral discovery after a privilege compromise"],
    close="Latency is padded to a floor, because the empty-result path is otherwise faster than the full one and that difference is readable across a few hundred queries. The padding also <em>reports when it failed to mask</em> — a floor cannot pad down, and silently failing is the same signal plus a belief that it was covered.",
))

UCS.append(dict(
    id="uc-04", num="UC-04", slug="the-core-loop",
    name="Establish a connection",
    favicon="🔌",
    h1='The core loop: <span class="accent">approve the relationship</span>, not every call',
    lede="This is the use case everything else supports. A developer asks for two tools on one server; a human approves once; and from then on the boundary is enforced by an artifact rather than by a process.",
    thesis="The approval is the enforcement mechanism.",
    today="A ticket. An unclear approver. Two to three weeks. At the end of it, a shared credential copied from a wiki page and a security control that enforces nothing.",
    flow=[
        ("1", "wc", "warden-connect", "Request", "Both parties, the exact tools, and why. Policy answers <em>instantly</em> whether it auto-approves: internal, read-only, unremarkable callee, and no human is needed."),
        ("2", "wc", "warden-connect", "Policy evaluates", "Structural preconditions first, which no rule may override — then the zone bar, then the first matching rule, then the standing caps, which may only <em>downgrade</em> an allow to require-approval."),
        ("3", "wc", "warden-connect", "Approve", "A detached signature from a named human's key — not a row in a table an operator with database access could write. Tier 1 needs two distinct approvers."),
        ("4", "wc", "warden-connect", "Mint", "One signed artifact per mediator, carrying <code>cid</code>, the pinned hashes, the surface, the terms, and a hard <code>exp</code>. Never multi-audience: that would be replayable across enforcement points."),
        ("5", "wc", "warden-connect", "Distribute", "Mediators <strong>pull</strong> and acknowledge exactly what they applied. A lost push is silent; a missed pull shows up as ACK lag an operator can alert on."),
        ("6", "wc", "warden-connect", "Verify at the mediator", "Eleven checks: signature, expiry, audience, revocation, both peer identities, the surface pin, posture, the zone pair, the token binding."),
        ("7", "wc", "warden-connect", "Filter <code>tools/list</code>", "The server offers three tools; the agent sees two. <strong>The model never learns <code>wire_funds</code> exists</strong>, so it cannot be manipulated into attempting it. This is prevention rather than detection."),
        ("8", "core", "Warden core", "Enforce each call", "Inside the surface, core decides every <code>tools/call</code> — scope, policy, ceilings, approvals. Two independent layers, neither able to widen the other."),
        ("9", "both", "both", "Record with <code>cid</code>", "Every action carries the connection id, so the relationship and the actions taken under it reconcile without anybody stitching logs together."),
    ],
    layers=[
        ("wc", "warden-connect", "The relationship boundary", "May these two parties be introduced at all, over what surface, on what terms, for how long. Answered once, recorded as a signed artifact, and enforced by the mediator's filter.", "surface ∩ terms ∩ exp"),
        ("core", "Warden core", "The action boundary", "May <em>this specific call</em> proceed right now. Scope, policy, budget, held approvals — evaluated per call, inside a surface it did not choose.", "token.scope ∩ policy_decision"),
    ],
    excs=[
        ("A1", "Requested surface exceeds the declared surface", "Rejected at request time with a precise diff. <strong>A contract is a ceiling, never a grant</strong> — it cannot conjure capability the callee never offered."),
        ("A2", "A cross-zone request", "Escalated to the zone-crossing path. Crossings between trust levels are denied until explicitly declared, and the declaration is directional: permitting egress to a partner does not permit that partner to reach back."),
        ("A3", "Approval not granted within the SLA", "The request expires and nothing is provisioned. Silence terminates; it never grants."),
        ("A4", "Hash mismatch at connect time", "Refused on the spot, and drift is raised. The pin is checked at <code>tools/list</code> — and the first <code>tools/call</code> triggers the mediator's own listing, so skipping discovery cannot skip verification."),
        ("A5", "Contract expired mid-workload", "The connection stops. There is no implicit grace: an expiry that quietly extends is not an expiry."),
        ("A6", "A ceiling breach", "Deny the call, notify the owner, keep the contract valid. A rate spike is not grounds to tear down a relationship."),
    ],
    evidence=["Signed contract", "Approval record with approver and ticket", "Per-connection lifecycle events", "Per-action rows carrying cid"],
    threats=["Tool misuse", "Privilege compromise", "Human-in-the-loop fatigue"],
    close="The whole design in one line: <code>effective = contract.surface ∩ token.scope ∩ policy_decision</code>. Each layer can only narrow, and removing either one does not silently widen the other.",
))

UCS.append(dict(
    id="uc-05", num="UC-05", slug="partner-federation",
    name="Cross-organisation federation",
    favicon="🤝",
    h1='Two organisations, no shared keys, <span class="accent">no catalogue exchange</span>',
    lede="A partner's agent needs to be reachable by ours. Neither side will hand over a directory, neither holds the other's keys, and both need to end up believing the same thing about one specific agent.",
    thesis="A self-signed statement is not evidence of its own keys.",
    today="A shared API key in a vault, an email thread agreeing what it may be used for, and no mechanism that notices when either of those stops being true.",
    flow=[
        ("1", "wc", "warden-connect", "Build the trust chain", "Signed entity statements from the leaf up to an anchor exchanged out of band. Verification walks <strong>down from the anchor</strong>, using the keys each statement above asserts — never the keys a statement asserts about itself."),
        ("2", "wc", "warden-connect", "Resolve one agent", "By capability, not by catalogue. The partner's signed card is fetched and <strong>pinned locally</strong>, so from this moment their surface is watched the same way an internal one is."),
        ("3", "wc", "warden-connect", "Apply the partner bar", "Signed card mandatory. Provenance mandatory. Short re-attestation interval. Human approval mandatory. Data classes and jurisdictions declared, or no contract."),
        ("4", "wc", "warden-connect", "DPO review", "Cross-border data flows are a named review step with the declared classes and jurisdictions attached, rather than a question somebody thinks of later."),
        ("5", "wc", "warden-connect", "Mint, tightly", "Short TTL, tight ceilings, an explicit oversight term, and <code>delegation.max_depth: 1</code> — pinned at 1 for a partner zone whatever the chain says. A partner agent may not sub-delegate onward."),
        ("6", "core", "Warden core", "Enforce egress per call", "Only declared data classes cross, only to declared jurisdictions. The relationship said what <em>may</em> flow; core decides each thing that actually does."),
        ("7", "wc", "warden-connect", "Appear in the register", "The connection lands in the third-party register with its termination path recorded — which is what a DORA filing needs and what an exit drill exercises."),
    ],
    layers=[
        ("wc", "warden-connect", "Whether, and on what ceiling", "Federation sets a <strong>third ceiling</strong> alongside the contract and local policy. It never names a tool: superiors narrow, never widen, and a subordinate claiming more than its superior permitted is refused rather than silently trimmed.", "chain ∩ contract ∩ local policy"),
        ("core", "Warden core", "Every crossing call", "Data class and jurisdiction checks are per-call decisions. The contract declares the envelope; core is what stops one call leaving it.", "egress term enforcement"),
    ],
    excs=[
        ("A1", "The partner's card changes", "Connection suspended <em>immediately</em>, re-approval required. External drift is treated more severely than internal, because you have no visibility into why it happened."),
        ("A2", "Federation anchor rotation", "Existing contracts run to <code>exp</code>; <strong>no new ones are issued</strong> until the anchor is re-verified out of band. A degrade, not a refusal — and the distinction is the operator's to act on."),
        ("A3", "The partner asks for deeper delegation", "Denied by construction. <code>max_depth</code> cannot be raised by the callee, so this is not a policy decision anyone can be talked out of."),
        ("A4", "Exit — contract end, breach, insolvency", "<code>connect quarantine partner:…</code> executes the tested exit and produces the evidence. An exit path nobody has run is a paragraph, not a control."),
    ],
    evidence=["Federation trust chain", "Partner supplier record", "Contract", "DPO review", "Exit drill record"],
    threats=["Spoofing", "Rogue agents", "Communication poisoning", "Cross-border data exposure"],
    close="Three rules make the chain worth anything: it must terminate at a <em>configured</em> anchor; <code>authority_hints</code> are recorded and <strong>never followed</strong>, because following them is a fetch-a-URL-of-the-attacker's-choosing primitive; and each statement must be about the entity the level above named.",
))

UCS.append(dict(
    id="uc-06", num="UC-06", slug="surface-drift",
    name="Detect and respond to surface drift",
    favicon="📉",
    h1='The rug-pull: <span class="accent">same tool</span>, different instructions',
    lede="A server you approved changes a tool's description to something that reads, to a model, as an instruction. Nothing about the call changes. This is the use case that most clearly <strong>cannot be served at the action layer</strong>.",
    thesis="An action-layer control sees a permitted call. That is all there is to see.",
    today="A dependency you approved in March behaves differently in June, and the only way anyone finds out is by reading the diff nobody diffs.",
    flow=[
        ("1", "wc", "warden-connect", "Re-fetch on the interval", "Every active party, on its tier's schedule, rate-limited per endpoint so assurance cannot become a denial-of-service against the tool server it is protecting."),
        ("2", "wc", "warden-connect", "Canonicalise and compare", "Against the pin. Per-item hashes make the comparison structural rather than textual, which is what keeps the noise low enough to leave switched on."),
        ("3", "wc", "warden-connect", "Semantic diff", "Tools added, removed, descriptions changed, parameters changed, endpoint moved. The diff is what an owner is shown — not a hash mismatch they cannot interpret."),
        ("4", "wc", "warden-connect", "Re-screen the new text", "The eight detectors again. A description that was clean in March and now contains an exfiltration instruction is exactly what this step exists for."),
        ("5", "wc", "warden-connect", "Classify", "<strong>Material</strong> if a contracted tool vanished or changed, the endpoint moved, an attestation stopped verifying, or the new text screens as poisoned. <strong>Benign</strong> otherwise — and \"nothing is contracted\" is carefully distinguished from \"we could not resolve what is contracted\"."),
        ("6", "wc", "warden-connect", "Suspend, by pin lookup", "Material drift suspends every contract referencing that manifest — one index lookup, not a scan. Owners get the diff, not an alert."),
        ("7", "wc", "warden-connect", "Re-approval re-runs admission", "Not a state flip. A new pin and new contracts, or nothing."),
    ],
    layers=[
        ("wc", "warden-connect", "Sees the surface change", "Drift is a property of the <em>relationship</em>: what you contracted for is no longer what is on offer. Detecting it needs a remembered baseline, which is what the pin is.", "connect posture --drift"),
        ("core", "Warden core", "Structurally cannot see it", "The call is still <code>get_balance</code>. The scope still permits it. The policy still allows it. Every action-layer check passes, correctly, on a tool whose meaning has changed underneath them.", "— no signal available —"),
    ],
    excs=[
        ("A1", "Drift found at connect time", "Refused on the spot, before the scheduled check would have run — then the same classification flow. The pin is checked on every listing, so drift cannot wait for a timer."),
        ("A2", "Benign drift under standing policy", "The pin is auto-updated and the event recorded. No suspension: a typo in an uncontracted tool is not an incident, and treating it as one is how a control gets disabled."),
        ("A3", "Repeated drift from one party", "Posture degraded, tier escalated, re-attestation interval halved. <strong>A party that constantly changes shape is a party to watch</strong>, even when each individual change is harmless."),
    ],
    evidence=["Old and new hashes", "Semantic diff", "Screening result", "Suspension and re-approval records"],
    threats=["Tool poisoning", "Rug-pull", "Cross-server shadowing"],
    close="Degradation is automatic; containment is authorised. A low posture score never quarantines — auto-quarantine on a computed score would hand anyone who can nudge the inputs an estate-wide denial-of-service primitive.",
))

UCS.append(dict(
    id="uc-07", num="UC-07", slug="emergency-quarantine",
    name="Emergency quarantine",
    favicon="🚨",
    h1='One verb, whole estate, and an honest answer about <span class="accent">what landed</span>',
    lede="It is 03:00 and an agent is exfiltrating. Marking it quarantined in the registry takes five milliseconds and proves nothing — it keeps working until every mediator holding one of its contracts stops honouring them.",
    thesis="Unconfirmed is not contained.",
    today="Scale the deployment to zero and hope nothing else holds its credentials. Scoping the blast radius means asking three teams and grepping deployment repos.",
    flow=[
        ("1", "wc", "warden-connect", "Quarantine", "One command, with a reason and an operator. Dual control at tier 1. The registry state becomes terminal — not a flag somebody can flip back."),
        ("2", "wc", "warden-connect", "Append to the signed feed", "Append-only, contiguously sequenced, each entry signed with the <em>revocation</em> key — separate from the issuer key, so an operator who can mint contracts cannot thereby cut them."),
        ("3", "wc", "warden-connect", "Name every connection", "The party first, as a backstop that holds even if the contract-set construction has a bug — then each affected <code>cid</code> explicitly, so a mediator does not have to derive the set itself."),
        ("4", "wc", "warden-connect", "Fan out", "Push is <strong>latency only</strong>. It moves the median under a couple of seconds instead of under the poll interval. Every failure is reported and none of them changes the guarantee, because mediators pull anyway."),
        ("5", "wc", "warden-connect", "Collect acknowledgements", "Signed, naming the sequence applied and the in-flight calls aborted. An HTTP 200 from a mediator is <em>not</em> a confirmation: it accepted a notification, which is not the same as having applied the order."),
        ("6", "wc", "warden-connect", "Blast radius, as of the cut", "Everything the party could reach and everything that could reach it, annotated with business service — because \"these three services stop\" is what a decision needs, not a list of four hundred ids."),
        ("7", "wc", "warden-connect", "Emit signed SETs", "Downstream systems and federated partners cut their own sessions, including ones that have never heard of warden-connect."),
    ],
    layers=[
        ("wc", "warden-connect", "Cuts the relationship", "Revocation is relationship-layer: the contract stops existing, so there is nothing left for any call to be inside. This is what makes containment one action rather than a hunt.", "connect quarantine <party> --reason …"),
        ("core", "Warden core", "Stops seeing calls at all", "Core is not asked to deny anything. The mediator refuses the connection before core is reached — containment by removing the boundary, not by tightening it.", "— no contract, no call —"),
    ],
    excs=[
        ("A1", "A mediator is unreachable", "Reported as <strong>not confirmed</strong>, never assumed benign — and the report states the bound: that mediator applies the cut within its own poll interval regardless. <em>An unconfirmed mediator is not an unbounded risk, and saying so precisely is more useful than either \"contained\" or \"unknown\".</em>"),
        ("A2", "Quarantine would break a critical service", "The impacted service list is surfaced with the decision. Containment is <strong>not silently downgraded</strong>: an override is an explicit, dual-controlled, logged act."),
        ("A3", "Clearing quarantine", "Requires full re-admission, not a state flip. You cannot restore a party you have not re-proved — and restoring should be harder than cutting."),
    ],
    evidence=["Quarantine order with reason and operator", "Per-contract revocations", "Propagation confirmations and non-confirmations", "Blast-radius report", "Emitted SETs"],
    threats=["Rogue agents", "Privilege compromise", "Resource overload", "Repudiation"],
    close="The report has an <code>unconfirmed</code> field rather than a footnote. A containment tool that reports success for a mediator it never heard from manufactures exactly the false confidence that makes an incident worse.",
))

UCS.append(dict(
    id="uc-08", num="UC-08", slug="shadow-detection",
    name="Shadow agent and shadow MCP detection",
    favicon="👻",
    h1='You cannot govern a relationship <span class="accent">you have never seen</span>',
    lede="Every estate has agents nobody registered and endpoints nobody approved. The first useful thing a control plane does is not enforcement — it is producing a truthful list.",
    thesis="Honest visibility beats fake enforcement.",
    today="Nobody knows the number. Asked how many agent-to-tool connections exist in production, the honest answer is a shrug and a guess that is too low.",
    flow=[
        ("1", "core", "mediator, observe mode", "Observe an attempt", "A connection referencing an identity or endpoint the registry has never seen. In observe mode it is allowed — behaviour is byte-identical to not having deployed anything."),
        ("2", "wc", "warden-connect", "Raise a finding", "With the observed surface, the endpoint, and the <em>inferred</em> owner — from workload identity, namespace, or repository. An unowned finding goes nowhere, so inference is the difference between a report and an action."),
        ("3", "wc", "warden-connect", "Aggregate and rank", "Into a shadow-estate view, ordered by risk signals: external endpoint, write-capable tools, sensitive data classes. A flat list of two hundred findings is a list nobody works through."),
        ("4", "wc", "warden-connect", "One-command remediation", "The owner is contacted with exactly two paths: register it, or decommission it. A finding that does not come with the fix is a nag."),
        ("5", "wc", "warden-connect", "Ratchet to enforce", "Per zone, when the estate is ready. The attempt is then refused and the finding is an incident — but the observe phase is what makes that switch survivable."),
    ],
    layers=[
        ("core", "mediator", "Sees the attempt", "The mediator is on the path in observe mode, which is what makes an unregistered connection visible at all. It is the only component positioned to notice.", "connect-mediate --observe"),
        ("wc", "warden-connect", "Knows it is a stranger", "Because it holds the register. A mediator can only tell registered from unregistered if something is keeping the list — that list is the whole product at this stage.", "connect posture --shadow"),
    ],
    excs=[
        ("A1", "The owner cannot be inferred", "Escalates to the platform team with the network and identity context captured. An unowned agent is a finding about the estate, not about a team."),
        ("A2", "The endpoint is external and unapproved", "Treated as an egress incident <strong>immediately, regardless of mode</strong>. Observe mode is a promise not to break internal traffic; it was never a promise to stay quiet about data leaving."),
    ],
    evidence=["Finding with observed endpoint, surface, timestamps", "Inferred owner", "Shadow-estate view over time"],
    threats=["Rogue agents", "Supply chain", "Unmanaged egress"],
    close="This is the rung that needs no permission from anyone: a register with owners, drift detection and an evidence chain, enforcing nothing and saying so loudly. An estate that deploys only this gets a truthful inventory — and a truthful inventory is what every later rung is built on.",
))

UCS.append(dict(
    id="uc-09", num="UC-09", slug="renewal-and-offboarding",
    name="Renewal, review and offboarding",
    favicon="🔁",
    h1='Expiry is the only access review that <span class="accent">actually happens</span>',
    lede="Standing privilege accumulates because nothing forces a second look. A contract that expires converts a review from something somebody should do into something that happens whether or not anybody does anything.",
    thesis="Silence terminates. It never renews.",
    today="Access granted in 2024 is still granted. The quarterly review is a spreadsheet nobody can verify, and revoking anything risks breaking a job whose owner has left.",
    flow=[
        ("1", "wc", "warden-connect", "Notify with real usage", "Thirty days ahead, and not just \"this expires\": the tools actually called, the volume, the spend, and the denied attempts. A renewal decision without usage data is a rubber stamp."),
        ("2", "wc", "warden-connect", "Owner elects", "Renew, renew with a reduced surface, or terminate. Three buttons, one of which is the default."),
        ("3", "wc", "warden-connect", "Re-run admission", "Identity, provenance, pin, screening. <strong>Renewal is a re-decision, not an extension</strong> — the party has had thirty days to change, and the whole point is to look again."),
        ("4", "wc", "warden-connect", "Propose surface reduction", "Tools granted but never called are dropped <em>by default</em>. This is the ratchet: least connectivity gets tighter on its own unless somebody argues otherwise."),
        ("5", "wc", "warden-connect", "Mint, or lapse", "A new contract with the narrowed surface, or the connection stops at <code>exp</code>. There is no third option and no grace period."),
        ("6", "wc", "warden-connect", "Retain the record", "For the regulatory retention period, with a demonstrable exit path. Terminating a relationship is a thing you have to be able to prove you did."),
    ],
    layers=[
        ("wc", "warden-connect", "Owns the clock", "The relationship has a lifetime and the artifact carries it. Nothing needs to remember to review: the contract stops working, which is a review that cannot be deferred.", "terms.exp"),
        ("core", "Warden core", "Stops mid-workload, correctly", "When the contract lapses, core has no surface to work inside and the calls stop. Uncomfortable, and exactly right — an expiry that quietly extends is not an expiry.", "no contract → no call"),
    ],
    excs=[
        ("A1", "No owner response", "The contract lapses at <code>exp</code>. This is the design decision that makes the whole thing work: <strong>the default is off</strong>, and inaction removes access rather than preserving it."),
        ("A2", "The owner has left", "Flagged as orphaned. The business service owner must reassign it or it lapses — an orphaned connection is authority nobody is accountable for, which is the same thing as authority nobody should have."),
        ("A3", "Re-attestation fails at renewal", "No renewal; the connection lapses on schedule. A party that cannot prove what it claimed thirty days ago does not get another thirty."),
    ],
    evidence=["Renewal decision with usage report", "Surface-reduction diff", "Termination record", "Retention reference"],
    threats=["Standing-privilege accumulation", "Orphaned authority"],
    close="The measure worth tracking is not \"connections renewed\" — it is <strong>the share of renewals that came back narrower</strong>. A system where the surface only ever grows has an expiry date and no ratchet.",
))

UCS.append(dict(
    id="uc-10", num="UC-10", slug="regulatory-export",
    name="Regulatory register and evidence export",
    favicon="📋",
    h1='A register that <span class="accent">declares its own gaps</span> is the one that survives an audit',
    lede="DORA, CPS 230 and an OSCAL feed all want the same thing: a list of dependencies with owners, terms and criticality, provably as of a date. The connection contract already <em>is</em> that record.",
    thesis="An incomplete register that says so is defensible. One that pretends is not.",
    today="Six weeks of a spreadsheet assembled from tickets, wiki pages and interviews, describing a state that was already out of date when the first cell was filled in.",
    flow=[
        ("1", "wc", "warden-connect", "One command, one date", "<code>connect export --format dora --as-of 2026-06-30</code>. Point-in-time means replaying the event log to that instant, not reading current state — so \"as of 30 June\" means what it says."),
        ("2", "wc", "warden-connect", "Enumerate the dependencies", "Party, owner, business service, criticality tier, jurisdictions, data classes, contract terms, approval record, exit path. Every column comes from a record that was already there."),
        ("3", "wc", "warden-connect", "External agents as ICT providers", "With contractual terms drawn from the connection contract itself. The unusual part is that the terms in the register are the terms being <em>enforced</em>, not a summary of a PDF."),
        ("4", "wc", "warden-connect", "Reference the anchors", "The export embeds the chain head and a signed checkpoint, so it is verifiable rather than merely asserted. <code>anchor_ref: none</code> is a stated claim, printed in the document <em>and</em> on the terminal of the person about to file it."),
        ("5", "wc", "warden-connect", "Declare the gaps", "Two kinds: estate gaps (unattested, degraded, quarantined, unpinned, dangling) and <strong>mandatory template fields with no source in this system</strong> — LEI codes, contract values, RTOs — each named with where to get it."),
        ("6", "wc", "warden-connect", "Feed the other systems", "OSCAL for the GRC platform, OCSF for the SIEM. Same underlying record, three renderings, no reconciliation."),
    ],
    layers=[
        ("wc", "warden-connect", "Holds the register", "Because it holds the relationships. A register of dependencies is a register of relationships, and the artifact that authorised each one carries the terms the filing needs.", "connect export --format dora"),
        ("core", "Warden core", "Supplies the action history", "Per-action audit rows carrying <code>cid</code>. The register says what was permitted; core's rows say what was actually done — and the <code>cid</code> is what joins them without a correlation project.", "audit rows, keyed by cid"),
    ],
    excs=[
        ("A1", "Gaps are present", "An explicit exceptions section, not a silent omission. <strong>A blank is worse than a declared gap</strong>, because a blank reads as a filed answer — and the field-level gaps are enumerated by name rather than summarised."),
        ("A2", "A historical as-of query", "Reconstructed from the event history and verified against anchors. Snapshots are deliberately unused there: a snapshot reflects state <em>after</em> its timestamp, and there is no way to unwind it."),
    ],
    evidence=["The export itself", "Chain head and anchor references", "Exceptions section", "Reproducible byte-for-byte"],
    threats=["Repudiation", "Regulatory finding"],
    close="Every generator is a pure function of the projection and its provenance — nothing reads a clock or the network. Ask for the same date twice and you get the same bytes, because an auditor who cannot re-derive the register cannot check anybody's working.",
))

# ---------------------------------------------------------------------------
# Render use-case pages
# ---------------------------------------------------------------------------

def render_uc(uc, prev_uc, next_uc, hub_href="#"):
    stages = "\n".join(stage(n, w, wl, h, p) for (n, w, wl, h, p) in uc["flow"])
    layers = "\n".join(layer(*l) for l in uc["layers"])
    excs = "\n".join(exc(t, h, p) for (t, h, p) in uc["excs"])
    ev = "".join(f'<span class="chip ev">{e}</span>' for e in uc["evidence"])
    th = "".join(f'<span class="chip th">{t}</span>' for t in uc["threats"])

    prev_link = f'<a href="{prev_uc[1]}">← {prev_uc[0]}</a>' if prev_uc else "<span></span>"
    next_link = f'<a href="{next_uc[1]}">{next_uc[0]} →</a>' if next_uc else "<span></span>"

    body = f'''<div class="page">

<header class="hero col">
  <p class="eyebrow"><a href="{hub_href}">warden-connect</a> · {uc["num"]}</p>
  <h1>{uc["h1"]}</h1>
  <p class="lede">{uc["lede"]}</p>
  <p class="byline"><span>{uc["name"]}</span><span>{uc["thesis"]}</span></p>
</header>

<section class="band col">
  <span class="num">01</span>
  <h2>What happens without it</h2>
  <p>{uc["today"]}</p>
  <div class="kicker"><span class="lbl">the claim</span>{uc["thesis"]}</div>
</section>

<section class="band">
  <div class="col">
    <span class="num">02</span>
    <h2>The flow</h2>
    <p>Each step is labelled with which layer owns it. The badge matters more than it looks: most of the confusion about this system is people expecting one layer to answer the other's question.</p>
  </div>
  <div class="col flow">{stages}</div>
</section>

<section class="band">
  <div class="col">
    <span class="num">03</span>
    <h2>Where the boundary is</h2>
    <p>Two layers, and neither can widen the other. Removing one does not silently loosen what remains.</p>
  </div>
  <div class="wide layers">{layers}</div>
</section>

<section class="band">
  <div class="col">
    <span class="num">04</span>
    <h2>The exception paths</h2>
    <p>Where the real design lives. A main flow describes the day everything works; these describe the days that decide whether anyone keeps the thing switched on.</p>
  </div>
  <div class="col excs">{excs}</div>
</section>

<section class="band col">
  <span class="num">05</span>
  <h2>What it leaves behind</h2>
  <div class="chips">{ev}</div>
  <h3>Threats this addresses</h3>
  <div class="chips">{th}</div>
  <p style="margin-top:1.6rem">{uc["close"]}</p>

  <div class="nav">
    {prev_link}
    <a href="{hub_href}">all use cases</a>
    {next_link}
  </div>
</section>

</div>'''
    return shell(f'{uc["num"]} · {uc["name"]} — warden-connect', body)


# Placeholder hrefs; patched after publishing.
for i, uc in enumerate(UCS):
    prev_uc = (UCS[i - 1]["num"], f'__URL_{UCS[i-1]["id"]}__') if i > 0 else None
    next_uc = (UCS[i + 1]["num"], f'__URL_{UCS[i+1]["id"]}__') if i < len(UCS) - 1 else None
    (OUT / f'{uc["id"]}.html').write_text(
        render_uc(uc, prev_uc, next_uc, hub_href="__URL_hub__")
    )

print(f"wrote {len(UCS)} use-case pages to {OUT}")

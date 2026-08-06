#!/usr/bin/env python3
"""Build the hub page and patch real URLs into every page in the set."""
import pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from gen import CSS, SCRIPT, shell, UCS, OUT

URLS = {
    "uc-01": "https://claude.ai/code/artifact/9b4d20c2-b93d-4f2e-93fd-d13e3f79ec97",
    "uc-02": "https://claude.ai/code/artifact/b0f2726c-b781-42d6-b343-486cbc17fb32",
    "uc-03": "https://claude.ai/code/artifact/5ae9cb75-cff5-4915-ae6f-efc09f6a78ef",
    "uc-04": "https://claude.ai/code/artifact/bc4e07dd-4e1a-4e7f-96d3-2ac97945fdad",
    "uc-05": "https://claude.ai/code/artifact/a0e167be-a069-4a7d-8b04-768df8323907",
    "uc-06": "https://claude.ai/code/artifact/f8444df4-f4de-4a21-b60a-447b3b4b42af",
    "uc-07": "https://claude.ai/code/artifact/c1643853-4902-4859-a69e-004702d2505a",
    "uc-08": "https://claude.ai/code/artifact/d7ada431-ced2-48d9-9f5e-6af16f512899",
    "uc-09": "https://claude.ai/code/artifact/dc803f6c-199b-4eef-971a-7408da20cc4d",
    "uc-10": "https://claude.ai/code/artifact/83a9ab75-0e86-4d40-9cfa-4fdf2e26b62f",
}

BLURB = {
    "uc-01": "Seven admission stages, each recording whether it passed, degraded, or was skipped. Ends with the agent holding zero connections.",
    "uc-02": "Capture the surface from the server itself, canonicalise it, hash it. Everything downstream is that one number.",
    "uc-03": "The fastest way to find a capability — and an answer a caller cannot mine for the estate's map.",
    "uc-04": "The core loop. Approve the relationship once; the artifact enforces it from then on.",
    "uc-05": "A partner's agent, reachable, with no shared keys and no catalogue exchange in either direction.",
    "uc-06": "Same tool, different instructions. The one an action-layer control structurally cannot see.",
    "uc-07": "One verb, whole estate, under a minute — and an honest report about which mediators confirmed.",
    "uc-08": "Producing a truthful list of what already exists. The rung that needs permission from nobody.",
    "uc-09": "Expiry converts a review from something somebody should do into something that happens.",
    "uc-10": "DORA, CPS 230, OSCAL. The contract already is the record; the gaps are declared, not blanked.",
}

STAGE = {
    "uc-01": "① see", "uc-02": "① see", "uc-03": "① see", "uc-08": "① see",
    "uc-04": "② govern", "uc-06": "② govern", "uc-09": "② govern",
    "uc-05": "③ prove", "uc-07": "③ prove", "uc-10": "③ prove",
}

cards = "\n".join(
    f'''<a class="card rise" href="{URLS[uc["id"]]}">
  <span class="id">{uc["num"]} · {STAGE[uc["id"]]}</span>
  <h4>{uc["name"]}</h4>
  <p>{BLURB[uc["id"]]}</p>
  <span class="go">read →</span>
</a>''' for uc in UCS)

EXTRA = r"""
.split{display:grid;grid-template-columns:repeat(auto-fit,minmax(19rem,1fr));gap:1px;
  background:var(--rule);border:1px solid var(--rule);margin:2.4rem 0}
.half{background:var(--ground);padding:1.6rem 1.4rem}
.half .who{font-family:var(--mono);font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;
  display:inline-block;padding:.12rem .5rem;border-radius:999px;margin-bottom:.7rem}
.half.a .who{color:var(--brass);background:var(--brass-w);border:1px solid var(--brass)}
.half.b .who{color:var(--teal);background:var(--teal-w);border:1px solid var(--teal)}
.half h3{margin:0 0 .6rem;font-size:1.05rem}
.half p{font-size:.92rem;color:var(--muted);margin:0 0 .8rem}
.half ul{list-style:none;padding:0;margin:.8rem 0 0;font-family:var(--mono);font-size:.76rem;color:var(--muted)}
.half li{line-height:1.75;margin:0}
.bars{display:grid;gap:.45rem;font-family:var(--mono);font-size:.74rem;margin:2rem 0}
.barrow{display:grid;grid-template-columns:minmax(7rem,8.5rem) 1fr;gap:.8rem;align-items:center}
.barrow .lab{color:var(--muted);text-align:right}
.track{height:1.7rem;background:var(--raised);border-radius:2px;position:relative;overflow:hidden}
.fill{position:absolute;top:0;bottom:0;display:flex;align-items:center;padding-left:.55rem;
  color:var(--ground);font-size:.72rem;white-space:nowrap}
.fill.a{left:0;width:80%;background:var(--brass)}
.fill.b{left:0;width:54%;background:var(--teal)}
.fill.c{left:10%;width:62%;background:var(--muted)}
.fill.d{left:10%;width:42%;background:var(--ink)}
.barrow.result .track{background:transparent;border:1px dashed var(--rule)}
.stat{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:1.4rem 2rem;margin:2rem 0}
.stat div{border-top:1px solid var(--rule);padding-top:.7rem}
.stat .n{font-family:var(--mono);font-size:1.5rem;color:var(--brass);display:block;line-height:1.2}
.stat .l{font-family:var(--sans);font-size:.8rem;color:var(--muted)}
"""

body = f'''<div class="page">

<header class="hero col">
  <p class="eyebrow">warden-connect · the capability set</p>
  <h1>Who may an agent<br><span class="accent">talk to at all?</span></h1>
  <p class="lede">Every control built for AI agents so far asks <em>may this action proceed?</em> That is the right question, and it is the second one. The first is <strong>who is this agent permitted to be connected to in the first place</strong> — and nothing was answering it.</p>
  <p class="byline"><span>Ten use cases</span><span>Two layers</span><span>One signed artifact</span></p>
</header>

<section class="band col">
  <span class="num">01</span>
  <h2>The gap, stated precisely</h2>
  <p>An agent gateway can tell you that <code>wire_funds</code> was called and refuse it. It cannot tell you why the agent could see <code>wire_funds</code> at all, who decided that, when the decision expires, or whether the tool still means what it meant when somebody approved it.</p>
  <p>Those are questions about a <em>relationship</em>, not about an action. They need a different unit of governance: not the call, but the <strong>connection</strong> — a named pair of parties, a bounded surface, terms, an owner, and an expiry.</p>
  <div class="kicker">
    <span class="lbl">the unit of governance</span>
    A connection contract: <em>these two parties, exactly these tools, on these terms, until this date, approved by this person.</em> Signed, so it is enforcement rather than documentation.
  </div>
</section>

<section class="band">
  <div class="col">
    <span class="num">02</span>
    <h2>Two layers that cannot widen each other</h2>
    <p>This is the whole architecture, and the source of most confusion about it. warden-connect and Warden core answer different questions and neither can loosen the other's answer.</p>
  </div>

  <div class="wide split">
    <div class="half a">
      <span class="who">warden-connect</span>
      <h3>The relationship boundary</h3>
      <p>May these two parties be introduced, over what surface, on what terms, for how long? Decided <strong>once</strong>, recorded as a signed contract, enforced by filtering what the agent can even see.</p>
      <ul>
        <li>registry · admission · pins</li>
        <li>policy · approval · minting</li>
        <li>drift · posture · quarantine</li>
        <li>federation · register · export</li>
      </ul>
    </div>
    <div class="half b">
      <span class="who">Warden core</span>
      <h3>The action boundary</h3>
      <p>May <strong>this specific call</strong> proceed right now? Decided <strong>per call</strong>, inside a surface it did not choose — scope, policy, budgets, held approvals, audit.</p>
      <ul>
        <li>session tokens · scope</li>
        <li>per-call policy · ceilings</li>
        <li>held approvals · DPoP</li>
        <li>audit rows, keyed by cid</li>
      </ul>
    </div>
  </div>

  <div class="wide bars">
    <div class="barrow"><span class="lab">callee declares</span>
      <div class="track"><span class="fill a">get_balance · list_transactions · wire_funds · …</span></div></div>
    <div class="barrow"><span class="lab">contract surface</span>
      <div class="track"><span class="fill b">get_balance · list_transactions</span></div></div>
    <div class="barrow"><span class="lab">token scope</span>
      <div class="track"><span class="fill c">read-only, this tenant</span></div></div>
    <div class="barrow"><span class="lab">policy decision</span>
      <div class="track"><span class="fill d">permitted now, this caller</span></div></div>
    <div class="barrow result"><span class="lab">effective</span><div class="track"></div></div>
  </div>

  <div class="col">
    <p style="font-family:var(--mono);font-size:.9rem;text-align:center;color:var(--muted)">
      effective = contract.surface ∩ token.scope ∩ policy_decision
    </p>
    <div class="aside"><strong>A contract is a ceiling, never a grant.</strong> Holding one does not authorise a call — it bounds what a call could possibly be. Every layer narrows; none widens. And the two couple through <em>two signed artifacts and one identifier</em> rather than a shared library, so either can be adopted without the other.</div>
  </div>
</section>

<section class="band">
  <div class="col">
    <span class="num">03</span>
    <h2>The ten use cases</h2>
    <p>Grouped by the order an estate actually adopts them. Each is a page of its own — the flow, which layer owns each step, the exception paths where the real design lives, and what it leaves behind as evidence.</p>
    <p><strong>① see</strong> needs permission from nobody and enforces nothing. <strong>② govern</strong> is the first time behaviour changes. <strong>③ prove</strong> is what a regulator, a partner or an incident review asks for.</p>
  </div>
  <div class="wide cards">{cards}</div>
</section>

<section class="band col">
  <span class="num">04</span>
  <h2>The one that decides everything</h2>
  <p>If you read one, read <strong>UC-06, surface drift</strong>. It is the clearest demonstration that this is a distinct layer rather than a feature of the existing one.</p>
  <p>A tool server you approved changes a description to text that reads, to a model, as an instruction. The tool name is identical. The parameters are identical. The call is permitted, the scope allows it, the policy passes — every action-layer check returns the correct answer about a tool whose meaning changed underneath it.</p>
  <div class="kicker">
    <span class="lbl">why an action layer cannot help</span>
    There is no signal at the action layer. Detecting this needs a remembered baseline of what was agreed — and remembering what was agreed is what a relationship layer is for.
  </div>
  <p>That baseline is a hash taken at onboarding (UC-02), compared on a schedule (UC-06), and it is the reason the other nine use cases can share one mechanism.</p>
</section>

<section class="band col">
  <span class="num">05</span>
  <h2>What is actually built</h2>
  <p>Not a design document with an implementation section. Roughly 30,000 lines of Rust, no async runtime, a deliberately thin dependency list, and two binaries — <code>connect</code> and <code>connect-mediate</code>.</p>
  <div class="stat">
    <div><span class="n">729</span><span class="l">tests, clippy clean at <code>-D warnings</code></span></div>
    <div><span class="n">76</span><span class="l">error codes, each with a fail direction and a test</span></div>
    <div><span class="n">19</span><span class="l">conformance vectors — a third party can interoperate without this code</span></div>
    <div><span class="n">49</span><span class="l">labelled screening cases, precision gated at 1.0</span></div>
  </div>
  <p>The claim that matters is verifiable rather than asserted: with Warden core's own policy set to permit everything, warden-connect alone blocks an uncontracted tool, <code>tools/list</code> returns two of three, and the upstream logs <strong>zero</strong> executions of the third. Two independent layers, demonstrated independently.</p>

  <div class="aside">
    The recurring lesson from building it, which shaped nearly every design decision above: the bug class here is not a control that is <em>wrong</em>, it is a control that <strong>reads as configured and does nothing</strong>. An anchor interval that never elapsed. A deny rule made inert by a glob. A tenant name that escaped its root. A gate that reported green having measured nothing. Every one was found by running the binaries, not by the test suite — which is why so much of this design is about making absence visible.
  </div>
</section>

<section class="band col">
  <span class="num">06</span>
  <h2>Three claims it has to keep</h2>
  <div class="tw"><table>
    <thead><tr><th>Claim</th><th>What would falsify it</th></tr></thead>
    <tbody>
      <tr><td><strong>A rug-pull is caught before it is used.</strong></td><td>A contracted tool's description changing without every contract referencing that pin being suspended.</td></tr>
      <tr><td><strong>Containment is estate-wide in under a minute, or says it is not.</strong></td><td>A quarantine report describing an unheard-from mediator as contained.</td></tr>
      <tr><td><strong>The register is defensible as of a date.</strong></td><td>An export that cannot be re-derived byte-for-byte, or one that blanks a field instead of declaring it.</td></tr>
    </tbody>
  </table></div>
  <p style="color:var(--muted)">Each is a test, not a sentence. That is the only difference between a security architecture and a security narrative.</p>
</section>

</div>'''

(OUT / "hub.html").write_text(shell("warden-connect — the capability set", body).replace(
    "</style>", EXTRA + "</style>"))

# Patch real URLs into every page, including the hub's own placeholder.
hub_url = "__HUB__"
for path in OUT.glob("*.html"):
    text = path.read_text()
    for uid, url in URLS.items():
        text = text.replace(f"__URL_{uid}__", url)
    text = text.replace("__URL_hub__", hub_url)
    path.write_text(text)

print("hub written; urls patched")

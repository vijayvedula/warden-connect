# Use cases

Ten use cases, one file each. Every file carries the same template — actors,
trigger, preconditions, main flow, a **sequence diagram**, alternate and
exception flows, postconditions, controls, evidence, threats and a success
measure.

| Use case | Stage | Primary persona | Command entry point |
|---|---|---|---|
| [UC-01 · Register and admit an agent](UC-01-register-and-admit-an-agent.md) | ① → ② | Agent Developer | `connect register agent` |
| [UC-02 · Onboard a tool server](UC-02-onboard-a-tool-server.md) | ① → ② | Platform Operator / AppSec | `connect register server` |
| [UC-03 · Mediated capability discovery](UC-03-mediated-capability-discovery.md) | ① | Agent Developer | `connect discover` |
| [UC-04 · Establish a connection](UC-04-establish-a-connection.md) | ② | Agent Developer | `connect request` → `approve` |
| [UC-05 · Cross-organisation federation](UC-05-cross-organisation-federation.md) | ③ | Third-Party Risk | `connect federate` |
| [UC-06 · Surface drift](UC-06-surface-drift.md) | ② → ③ | AppSec | `connect posture --drift` |
| [UC-07 · Emergency quarantine](UC-07-emergency-quarantine.md) | ② | SecOps | `connect quarantine` |
| [UC-08 · Shadow estate detection](UC-08-shadow-estate-detection.md) | ① | CISO | `connect inventory` |
| [UC-09 · Renewal, review, offboarding](UC-09-renewal-review-offboarding.md) | ② → ③ | Service owner | `connect contracts --dormant` |
| [UC-10 · Regulatory register and evidence](UC-10-regulatory-register-and-evidence.md) | ③ | Risk & Compliance | `connect export` |

**The wedge.** UC-01, UC-02, UC-03 and UC-08 all land in stage ① and require no
behaviour change from any developer. The estate becomes visible before anything
becomes enforced.

**Actor glossary.** *Agent Developer* builds and owns an agent · *Security
Architect* approves connections · *AppSec Engineer* owns surface and supply
chain · *SecOps Analyst* owns containment · *Platform Operator* runs the plane ·
*Risk & Compliance Officer* owns evidence · *Partner Agent Operator* is external ·
*Calling Agent* and *Callee* are the non-human actors.

# MITRE ATLAS (16 tactics)

**Status: Full**
**Source**: [issue #145](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/145) · fix: [issue #165 / PR #166](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165) (SkillRegistry)
**Reference**: [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) — [`ATLAS.yaml`](https://github.com/mitre-atlas/atlas-data/blob/main/dist/ATLAS.yaml), an ATT&CK-style kill-chain for attacks against AI systems (16 `AML.TA####` tactics)
**Last verified**: 2026-09-28

## Scope note

Like MAESTRO ([#144](144-csa-maestro.md)), ATLAS is not a checklist of controls but an ATTACK model — each tactic is a step an adversary follows, not a requirement to satisfy. The mapping below answers "what in TBP prevents or limits an adversary from reaching this step?" rather than "does TBP implement this control?"

Legend: ✅ Structurally covered/mitigated · 🟡 Partial · 🔴 Real gap · ⚪ Out of TBP's scope (the step happens before any contact with TBP, or outside its layer)

## The 16 tactics vs. TBP

| Tactic | What it describes | Status | Detail |
|---|---|---|---|
| **Reconnaissance** (TA0002) | Adversary gathers info about the target system | ⚪ | Happens entirely before any contact with TBP. |
| **Resource Development** (TA0003) | Adversary establishes attack resources | ⚪ | Attacker infrastructure, never touched by TBP. |
| **Initial Access** (TA0004) | Adversary seeks access to the AI system | ✅ | Exactly the authenticated-transport doctrine: Unix socket 0660 + `SO_PEERCRED`, mandatory mTLS for network access (#124, `ClientAuth: RequireAndVerifyClientCert`) — unauthenticated access never reaches the application mux. |
| **AI Model Access** (TA0000) | Adversary seeks access to the model itself | ⚪ | TBP never hosts or serves the model — this resource is upstream of the broker, out of scope by construction. |
| **Execution** (TA0005) | Trigger execution of malicious code/artifact | ✅ | The core of TBP's doctrine: "the action executed is the translated action" (§4.5) — model output never directly triggers execution, it passes through translator→OPA→quorum→contract before token emission. |
| **Persistence** (TA0006) | Maintain a foothold via AI artifacts | ✅ | Closed by `SkillRegistry` (#165, PR #166): an agent can no longer make an action/artifact exist merely by naming it — it must match a registered skill with an explicit resource scope. |
| **Privilege Escalation** (TA0012) | Obtain higher permissions | ✅ | Named-closed by #125: class/quota resolved by the broker's registry, never accepted as declared by the caller — an agent cannot self-promote. |
| **Defense Evasion** (TA0007) | Evade detection by AI security software | 🟡 | TBP isn't a detector to quietly bypass — it's an enforcement point: bypassing it means being refused (fail-closed), not going unnoticed. Systematic alarm doctrine (`OnTrip`, T14) makes a refusal always loud, never silent — but TBP doesn't claim to DETECT an evasion attempt upstream of itself. |
| **Credential Access** (TA0013) | Steal credentials | ✅ | Private key never extractable from the HSM (review #114, `CKA_EXTRACTABLE=false` check), issuer seed at 0600, devmode doctrine (#113) against custody escape hatches. |
| **Discovery** (TA0008) | Map the target AI environment | 🟡 | Hash-only leaves (§6.2) limit what a read of the registry actually reveals — even a full audit-chain read doesn't expose the business content of decisions. |
| **Lateral Movement** (TA0015) | Move within the AI environment | 🟡 | Inter-cell fencing (T29, epoch authority, quarantine §7.3) bounds the blast radius of a compromised cell; VLAN segmentation (`deploy/router-debian.md`) does the same at the network level. |
| **Collection** (TA0009) | Gather AI artifacts and related information | 🟡 | Same logic as Discovery — hash-only structurally limits the value of any registry collection. |
| **AI Attack Staging** (TA0001) | Leverage knowledge/access already gained | ⚪ | A consequence of prior steps, not a step TBP specifically intercepts. |
| **Command and Control** (TA0014) | Communicate with a compromised AI system to direct it | ✅ | "No direct client → server path" plus authenticated transport (see Initial Access) structurally prevent an unauthorized C2 channel to the broker. |
| **Exfiltration** (TA0010) | Steal AI artifacts or system information | ✅ | **The strongest answer in this whole catalog series**: even a total read compromise of the registry yields only salted hashes (§6.2) — no business content was ever written there to begin with. |
| **Impact** (TA0011) | Manipulate, disrupt, erode trust in, or destroy the AI system | 🟡 | Generalized fail-closed bounds the worst case to a denial of service, never silent corruption — but TBP can do nothing for an upstream-compromised agent whose individual actions remain, each, policy-compliant. |

---

## Summary

**Strongest result of the whole series**: **Exfiltration** — the hash-only doctrine (§6.2) isn't a bolted-on mitigation, it makes this category structurally unproductive for an attacker. Worth leading with in any TBP security pitch.

**Closed since the original catalog**: **Persistence**, by `SkillRegistry` (#165, PR #166) — the fourth independent framework (after [#142](142-owasp-agentic-skills-top10.md), [#143](143-owasp-llm-top10.md), [#144](144-csa-maestro.md)) that pointed at this same gap, now resolved. No other 🔴 remains in this catalog.

**Posture nuance to keep in any security writeup**: TBP must never claim to be a detection system — its role is a fail-closed enforcement point. An adversary who bypasses it is refused, not undetected.

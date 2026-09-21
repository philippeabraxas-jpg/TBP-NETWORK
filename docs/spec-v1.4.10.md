# TBP — Attested action governance
## Technical note v1.4.10 · 18 September 2026 · Philippe Collet

_Version française : [spec-v1.4.10.fr.md](spec-v1.4.10.fr.md)._

> *"Existing access control decides whether you get in; TBP decides what you can do once inside — and proves it. We govern capabilities, not models."*

TBP does not replace business protections: the power plant has its locks, the LLM has its guardrails. TBP provides a switch that can be activated and audited. If the translator does not know, it does not authorize: it asks. If the business says no, the action dies. If the business says yes, the action goes through. If it is grey, the action is submitted.

**Integrates:** independent adversarial audits (Gemini, DeepSeek, Claude — v1.1–v1.3) · practical four-evaluator audit + two meta-audits (deployment reference v1.2) · network manifesto (integrated and normalized).

**Implementation**: this document is part of the [TBP-NETWORK](https://github.com/philippeabraxas-jpg/TBP-NETWORK) repository — see the [README](../README.md) for the repository structure, the deployment sequence (§13) and the starting configurations (`config/`, `policies/`).

---

## 0 · Summary

TBP governs **agent capabilities**, not their models. An LLM is probabilistic: security can never depend on what it produces — it depends on what its action is allowed to do, verified by a deterministic system before execution, with third-party-verifiable proof.

![Figure 1 — The TBP governance chain](figs/fig1_chaine.png)

**New in v1.4**: bounded-capability passports (signed quota, counter at the PEP, per-epoch egress envelope, metadata telemetry) · ephemeral keys · explicit time (NTS) · arbitrated plan = contract · jti anti-replay · OPA circuit breaker · classification governance · normalization glossary · epistemic status.

## 1 · Doctrine

- **Never by trust, always by verifiable proof** — every claim is a cryptographic property, not a declaration.
- **Never by name, always by signature** — a name can be copied; a signature over (object, time, scope) cannot.
- **Never by yes, always by default-deny** — the unknown is classified strict (including APIs with no declared invariants).
- **Defeasible but detectable** — we do not claim "impossible", we claim "impossible to hide".
- **We govern capabilities, not machines** — the question is not "can one get in without going through the router" (always yes) but "what can one reach" (bounded) and "who will see it" (proven).
- **TBP is not a judge, it is a book of laws and a registry office** — it mechanically applies rules already written by the business; no discretion is exercised at execution. It produces a three-position state: rejected (business rule or translator), authorized (nothing in TBP prevents it), submitted (grey — the only admitted discretion, and it is human). Security remains carried by the business rules; TBP makes it activatable, signed and auditable.
- **The executed action is the translated action** — the translator produces the action; the agent's lying about its intention is structurally sterilized.
- **A lied-about decision remains attributable** — a compromised component can lie about the decision, not about its responsibility.
- **We do not close every hole; we classify them by impact and mitigate proportionally** — governance is an allocation problem, not a completeness problem.

| Object | Mechanism | Analogue |
|---|---|---|
| Rules | versioned packages, hash-pinned (constrained language, §11) | lockfile / SPDX |
| Components | signed packages, verified at install | package manager (Sigstore) |
| Actions | signed tokens (action + time + scope + quota) | — |
| Entities | attestation bound to policy (handshake) | mTLS + TEE attestation |

## 2 · Threat model

**Attackers**: malicious or hijacked agents, ungoverned machines, insiders, and an attacker able to take down, **isolate**, replace or **overwhelm** components — including by controlling **timing** (delays, partitions, windows).

**Not covered by prevention** (covered by detection): hotspot/4G, local models, physical access to an ungoverned machine.

**Trust assumption**: governance keys (HSM, m-of-n); at least one independent monitor; authenticated out-of-band channel for genesis; controllers reachable over a separate channel (§7.2).

## 3 · Inter-entity handshake

The handshake proves three things: **(1) under which rules the entity operates** (`policy_id = hash(P)`, mechanical subsumption); **(2) that its history is continuous** (O(log n) consistency proof; any modification is a signed transition event; discontinuity = corruption = refusal); **(3) that it is operational right now** (verifier nonce → real OPA cycle → leaf → HSM signature; targets accepting only tokens issued in-flight).

![Figure 2 — Handshake](figs/fig2_handshake.png)

### 3.2 · Bootstrap: genesis, late joiners, legitimacy limit

Epoch 0 is signed by the controller quorum and externally anchored from genesis. The late joiner verifies the key chain (out-of-band), an O(log n) consistency proof, and the continuity of transitions. **Explicit limit**: bootstrap proves non-tampering, not legitimacy — the parallel-genesis attack (TOFU) passes every consistency check; legitimacy comes from the referenced directory (eIDAS type), outside the protocol.

### 3.3 · Differentiated treatment

| Presented state | Treatment |
|---|---|
| Attested, subsuming policy | calibrated passage according to classification |
| Non-attested / unknown | strict tier: side effects blocked or arbitrated, bounded egress |
| Unexplained discontinuity | refusal + monitor alarm |

**Positioning**: TBP is neither NAC, nor Zero Trust (NIST SP 800-207), nor entity authentication (PKI, APKI, SPIFFE). It adds: action semantics, the human-arbitration tier, third-party-verifiable proof.

## 4 · Action signing (machine level)

### 4.1 · Mechanism and classification

Signed token (Ed25519, TTL 30–60 s, scope = action + resource, unique jti) issued after OPA decision; **local PEP** validates signature + freshness + scope + non-consumption. Debian: `nftables redirect`; Windows: PEP service. Every decision leaves a leaf in the cell chain.

- **Harmless** (read-only) → direct execution, sub-ms.
- **To arbitrate** (side effect) → human validation.
- **Out of scope** → immediate refusal + reformulation proposal.

### 4.1-bis · Bounded-capability passports

Any heavy-path opening (session, tunnel, SDN rule) is issued as a passport: a token extending the action token with a quota vector `(resource, operation, max_volume, window, TTL, jti)` — cryptographically bound and signed, never in an out-of-band modifiable rule.

- **Counter at execution** (PEP / terminator): decrements the volume; lightweight data-plane state, short TTL — same pattern as the jti cache; a session has a single terminator. Overrun = clean cut + refusal + leaf.
- **Egress envelope at issuance** (broker): aggregate quota per entity and per epoch, evaluated by OPA at issuance — closes the aggregation of legitimate passports.
- **Metadata telemetry**: bytes per interval, destination, pace (NetFlow/IPFIX style); registry leaves. **Content inspection of passport flows is prohibited** — it would destroy the data-plane speed gain: anti-dribble relies exclusively on post-processing flow metadata (trickling, sub-threshold exfiltrations).
- **Doctrine**: prevent what costs little, detect what costs much — every open door is born with its counter and its instrument (§5.3).

![Figure 5 — Bounded-capability passport](figs/fig5_passeport.png)

*Separation of temperatures: quota = counted at execution (PEP); envelope = counted at issuance (broker).*

### 4.2 · Arbitration is a signature, not a read

The plan presented to the operator is generated by the agent (probabilistic) and could lie (benign abstract plan masking a destructive path). Countermeasure: **the approved plan is a contract** — execution is verified against the hash of the validated plan; deviation = refusal.

### 4.3 · Anti-replay

Signature + freshness + scope do not answer "already consumed?". Each PEP keeps a **consumed-token cache with bounded TTL**; every execution leaf carries the jti. Replay bounded to N replicas reachable per TTL window (spec parameter); F/W classes closed by service-side idempotence.

### 4.4 · Order → effect gap (semantic aliasing)

Effect integrity belongs to the business. The PEP validates the envelope, not hidden effects (triggers, cascades). Mitigations bounded to F/I/W classes, on two levels — **per action** then **per sequence** — because a policy that judges only one action at a time can, by construction, never see an effect that exists only at sequence level.

**Per action**: (1) **dry-run with state diff** submitted to OPA before commit; (2) object-capabilities (token sealed on object/field/value hash); (3) **in-process PEP** — for PostgreSQL, extension blocking at `post_parse_analyze` (pre-planner: `ExecutorStart` alone is post-planning, a side-effecting function may already be evaluated there); (4) contract-driven — **an API with no declared invariants is classified W**.

**Per sequence**, inherited from the policy engine of the protocol repository (Responsible-Alliance-Protocol — see README, *Relation to the main TBP repository*): (5) stateful behavioral profile, per agent — 24 h / 7 d sliding windows (cumulative amount and count, burst frequency, behavioral drift as deviation from an EMA baseline, similarity and temporal anomalies); versioned composite score as a **first-class OPA input**, never an out-of-policy heuristic (e.g. 24 h cumulative beyond threshold without human approval = refusal, whatever the individual status of each action composing the cumulative). Closes the class where the "salami" attack (N sub-threshold actions, aggregate effect above) escapes by construction from (1)-(4), which only ever evaluate the current action.

**Residue, anticipated for ex-post rather than ex-ante closure**: an isolated, large-scale action whose effect deviates from intention without being intercepted by (1)-(5) remains possible — this is the business residue of §10 point 5. It is not left without a documented answer: the identified closure path is a **mandatory post-mortem with reconstruction of the intention → effect drift**, feeding back to recalibrate the F/I/W thresholds — but this path belongs to the optional TBP-GOVERNANCE module (Responsible-Alliance-Protocol), not to the core scope of TBP-NETWORK; see §11.9 for the exact status and why this module deliberately stays out of the default deployment.

### 4.5 · The translator: structural anti-fraud and measured quality

**Doctrine**: the executed action is the action *translated* by the local semantic guard — the agent's lie about its intention never propagates to the effect. The residue is a **quality error**, handled by two independent layers: the translator reduces probability (decomposition, multilingual, 7–8B fine-tuned, constrained JSON grammar, vLLM), the rules reduce impact (default refusal of uncovered actions; error toward a covered and harmless action = bounded quality damage).

- **Quality governance**: per-class differentiated precision; native corpus per language, positive and negative; shadow mode; continuous measurement (corpus replay at every update + human sample).
- **Anchored metrics**: FNR < 0.1%, FPR < 2%, computed per epoch, recorded in the master chain. **Leaf format: aggregates + corpus hash — content never in cleartext** (connects §11 privacy to the leaf schema).
- **Controlled degradation**: threshold breach = tier-shift or bundle revocation; translator failure = natural-language rejection, structured only, no cloud fallback.

**The translator is not the security element** (doctrine above): it is never the one judging an action safe or dangerous — it is the *produced* action that is judged by the rules, without exception (default-deny, §1). A translation error therefore never circumvents judgment: it changes which action is submitted to it, not whether that action, once submitted, is correctly judged. The residue is therefore not "security circumvented by a bad translation" — the rules apply, without fail, to what the translator actually produces, however imperfect that product may be. A narrower residue exists: a misclassified action (wrong domain, missing tag — §11.8) may miss the rule written for its true class, when that rule is conditioned on that field rather than on the direct content of the action; default-deny (§1) bounds this risk for the uncovered action (unknown = strict), not for the covered but mislabeled action.

But this residue itself remains **bounded by the passport, not by the rule it missed**: the token issued after OPA decision has the precise action + resource as its scope (§4.1), sealed on object/field/value for capabilities (§4.4 (2)) — never a blank check on the class. The PEP revalidates this scope at execution, independently of the OPA branch that issued the token (§4.1); any action that does not exactly match the presented token, or for which no valid token exists, is stopped cold. An erroneous classification can therefore never widen what an action can do — it can, at worst, cause a token to be wrongly issued for **one** precise, sealed and audited action (every decision leaves a leaf, §4.1), which should have been refused or submitted to arbitration. It is an occasional bad verdict on a bounded action, never a loophole in the bounding apparatus itself. It is the quality of this verdict — not the bounding — that remains the least mature part of the system (metrics above, §15); and the verifiable heaviness of the rest of the chain (dry-run diff, object-capabilities, pattern-analysis §4.4, Merkle, multisig) must never be read as if it reduced the risk of a bad verdict — it bounds and audits what that bad verdict can concretely do, which is already the essential.

The translator is a friction parameter, not a security parameter: it illuminates the action, it never decides it. It does not say "dangerous" or "safe"; it says "I know how to translate" or "I do not know". Its quality does not determine safety — it determines the escalation rate and therefore the tenability of the friction budget (§9.1). An over-cautious translator exhausts the operator; an over-confident one lets mistranslated actions through, caught by the business rules or by default refusal. The relevant metric is therefore not only FNR/FPR in the strict sense, but escalation rate and correct-translation rate excluding refusals. The safety of F/I/W classes remains carried by the rules, the quorum (§7.5) and human arbitration.

- **Runtime hardening** (vLLM/PyTorch): dedicated non-root process, CAP_DROP_ALL, strict seccomp — dm-verity protects the image at rest, not the runtime surface.

## 5 · Enterprise network architecture

### 5.1 · The wall and the switching

No direct client → server path; the server accepts only the broker. The NAC is a **switch** in the railway sense: authenticated (802.1X, EAP-TLS) → VLAN giving access to the broker; unknown → **captive VLAN** whose only route is enrollment or the forced broker. EAP-TLS reuses **the same PKI as the handshake** — a single identity infrastructure. L2 anti-bypass: strict server VLAN, DHCP snooping + DAI, AP isolation.

![Figure 3 — Network topology](figs/fig3_reseau.png)

### 5.2 · Catalogue of paths bypassing the router

| Path | Closed by | Residue / compensation |
|---|---|---|
| East-west workstation→workstation | switch ACLs, AP isolation, host firewalls | same-VLAN → strict segmentation |
| Hardware (USB, Thunderbolt) | USBGuard, GPO, BIOS/IOMMU | endpoint, not network |
| Hotspot / 4G | — (cannot be funded shut) | resource PEP · instrumented |
| Local model | — | we do not govern the brain |
| Console / iLO / admin | mgmt VLAN, jump hosts, logged acts | admin = most audited entity |
| Unregistered workstation | NAC → forced broker / captive VLAN | — |

### 5.3 · Hole doctrine

> *An uninstrumented hole in the wall is a door. An instrumented hole is a sensor.*

"Instrumented" requires a **named instrument**: host telemetry (file integrity, logs, flows) **fed to the registry**. A channel without an instrument leaves acts unprevented and unseen — the only forbidden state.

| Class | Examples | Requirement |
|---|---|---|
| F — financial | payment, ERP write | token PEP + arbitration + quota |
| I — infrastructure | prod, CI/CD | token PEP + strict scoping |
| W — survival | mass effect | PEP + arbitration + quorum (§7.5) + §4.4 |
| outside F/I/W | read, internet | wall + audit (conditions 1 or 3) |

- **Telemetry is a class-W action**: cutting it — even by an admin under pressure — requires a quorum, is signed, alarmed, recorded.
- **Factory fail**: the "RADIUS unreachable" default is often fail-open — force fail-closed per switch. OCSP/CRL unreachable = remediation VLAN with feedback, never blind soft-fail.
- **Deployment**: monitor mode before closed; no RADIUS-assigned VLAN in v1; MAB = instrumented channel (dedicated IoT VLAN, never silent).

## 6 · Registry: two-level architecture

Each cell keeps its own chain (sessions, batches) — hot path without coordination. Periodically, `hash(broker_id, head, TSA)` of each cell is recorded in the **master chain** (CT pattern, RFC 6962). Engine: **Tessera** (GA library, POSIX driver — one directory = one cell log); bootstrap: veritrail (test against RFC 6962 vectors); Rekor/cosign = **artifact** registry (§1), never decisions. Fully in-house ruled out: leaf/node domain separation is the most audited part of the ecosystem — and third-party-verifiable proof loses its value if the auditor has to re-read the code. Ecosystem signal: Let's Encrypt is migrating its RFC 6962 logs to the Static CT / tiled API — the Tessera direction is that of the entire field.

![Figure 4 — Two-level registry](figs/fig4_registre.png)

### 6.2 · Temperatures — and explicit time

| Path | Role | Tolerated failures |
|---|---|---|
| Hot: broker + OPA + HSM | decision, token | N+1 stateless, failover in seconds |
| Warm: registries | recording, sequencing | replicated, idempotent |
| Cold: anchoring + monitors | external proof, detection | third parties, store-and-forward |

- **Bounded maximum lag**: the epoch token carries the hash of the last anchoring; the PEP refuses any token whose anchoring shows a lag > threshold (default 120 s). Closes overwhelming: DoS, never an impunity window. Complement: dynamic tier-shift under load.
- **Time = explicit founding assumption**: TTL, epochs, TSA and freshness inherit a synchronized-clocks assumption. Requirement: **NTS (RFC 8915)** on brokers/PEPs, drift < 5 ms — otherwise mass rejection of legitimate tokens = systemic friction.
- **GDPR / retention**: an infinite append-only enters tension with retention obligations — hash-only leaves, salting, explicit retention policy.

### 6.3 · Attested state = manifest

`(policy_id, OPA config, broker hash, local AI container hash, chain head)` — any component change = visible, signed, continuous transition; the hash is that of the signed package (§1). Measured boot: the node's root is measured by the TPM/HSM at startup.

## 7 · Cluster: cells, epochs, mirrors, canary

### 7.1 · Cattle, not root of trust
The broker is not the root of trust; the keys and the master chain are. Per-cell state; system state lives in the master chain + the current epoch. **The Supervisor is a widened-scope cell + the master registry** — same mechanics, same doctrine, never a new black box.

### 7.2 · Per-epoch fencing
Epoch token `(N, authority, TTL ~60 s)` signed by the controllers (m-of-n, HSM); only the holder serves; the old one expires by itself — two authorities impossible. Manual failover: controllers reachable over a separate channel. Pre-authorized automatic ("max N failovers/hour, then human"); 3 cells + 2-of-3 majority.

### 7.3 · Revocation = new epoch
Compromised cell: epoch with reduced roster; dead tokens; **quarantine, not murder** — the frozen cell serves analysis.

### 7.4 · Mirrors and canary — anchored window
Bundle hash anchored every epoch (policy_id = hash of rules = the handshake hash). **The healthy window is defined and anchored in the master chain — never measured by the canary itself** (a network attacker can isolate it during measurement); promotion = proof of receipt of the anchored bundle. An eligible cell satisfies all committed external requirements.

### 7.5 · Quorum
Class-W actions: k-of-n co-signature; a single cell cannot authorize the maximal irreversible.

### 7.6 · Compromise between two epochs — provenance ≠ compliance
During the TTL of the active epoch, a component holding its local keys can issue allow tokens the policy would not have authorized. What remains proven: attributability (*it can lie about the decision, not about its responsibility*), the temporal bound, W protection, the impossibility of rewriting the past. **Explicit trade-off**: the local OPA makes this fraud possible; remote co-evaluation would close it at the price of latency — positionable per class (default: local tier 1, co-evaluation F and W).

### 7.7 · Policy evolution (agility under contract)
Verifiable monotonicity (§11); legitimate weakening = motivated, visible transition updating verifier consent; negotiated workflow without stop or window; historically continuous compliance.

![Figure 6 — Key hierarchy and time](figs/fig6_cles.png)

## 8 · Threats ↔ mechanisms matrix

| Threat | Mechanism | Residue |
|---|---|---|
| Multilingual prompt injection | deterministic floor + translator + auditor | rate < 100% (bounded) |
| Description fraud (lying agent) | translator: the executed action is the translated action | structurally closed |
| Translation error | rules (default refusal) + measured quality (§4.5) | bounded quality damage |
| Lying abstract plan in arbitration | approved plan = hashed contract | — |
| Semantic aliasing | business primary + §4.4 mitigations per action and per sequence (F/I/W) | business residue: anticipated ex-post closure, optional module (§11.9) |
| Token replay | jti + PEP cache + F/W cardinality | bounded to N replicas; detectable |
| Open tunnel (passport) | quota passport + envelope + metadata (§4.1-bis) | dribble → post-processing |
| Local PEP bypass | service re-validation / peer credentials / eBPF cgroup | — |
| Ungoverned machine | NAC switching; wall; resource PEP | hotspot/local model: detection |
| Broker down / adverse | stateless N+1; fencing; pinned keys | alarmed DoS — never an act |
| Split-brain | TTL epochs; 2-of-3; OOB controllers | — |
| Registry overwhelming | bounded lag + tier-shift | DoS — never impunity |
| Canary promotion under partition | anchored healthy window + proof of receipt | — |
| Compromised cell intra-epoch | TTL + revocation + W quorum | attributable acts, post-facto detection |
| Governance key theft | m-of-n; HSM; quorum | future signable, past sealed |
| Poisoned bundle | signature + anchored canary | limited canary window |
| Parallel genesis (TOFU) | — (assumed) | legitimacy = referenced directory (§3.2) |
| Admin under pressure (telemetry cut) | telemetry = W action (quorum, alarm) | root trust assumed elsewhere |
| Death by friction | bounded F/I/W scope + indicators (§9) | operational risk #1 |

## 9 · Real cost and withdrawal conditions

**Target latencies**: tier 1 < 2–5 ms; tier 2: 10–50 ms; tier W: seconds to minutes. **The cost regime changes**: from a rare and catastrophic cost to a continuous and visible one. Avoided acts are invisible; frictions are daily. **Warning indicators**: arbitration > 20%; validations < 5 s; uninstrumented holes; lengthening TTLs; exception culture.

**Three withdrawal scenarios**: (A) break-glass — disengagement = governed action; (B) death by friction (the most likely) — countermeasure: strictly govern F/I/W; (C) DoS cascade — price = assumed loss of provability.

### 9.1 · Friction budget — founding constraint of the pilot

The architecture is usable *because it accepts being imperfect*; this constraint is a measurable requirement, not an intention:

- **Added tier-1 latency < 5 ms** (deterministic floor, continuously measured).
- **Target human-arbitration rate < 10%** of actions (beyond: governance becomes the bottleneck — §9 indicator). This rate is directly a function of translator quality (§4.5): it is the main adjustment lever of the friction budget.
- **Pilot failure condition: measured user-experience regression = 0** — protection must never be paid for by blocking legitimate tasks.

**Decision threshold**: keep TBP iff P(irreversible act) × cost(act) > cost(DoS) + cost(friction).

**Time-to-Audit** (< 1 week vs 3–6 months): commercial metric — proof chain to be built before customer use.

## 10 · What the system does not claim

1. Not 100% secure — **100% auditable on declared scope**.
2. The translator is probabilistic; the guarantee is the floor.
3. Attestation commits the rules, not their perfect execution.
4. The hotspot / local-model channel is incompressible.
5. The real effect of an action remains the business's responsibility.
6. Intra-epoch fraud is possible and bounded (§7.6).
7. Genesis legitimacy is not provable by the protocol.
8. The root admin remains a trusted actor — the most audited one.
9. Availability has a price.
10. Compliance (AI Act art. 14) is the entry price of human arbitration; TBP amortizes it.
11. TBP is not a judge, it is a book of laws and a registry office: it illuminates the action and makes it activatable, signed, auditable, without exercising discretion. The safety verdict belongs to the business rules (already written) and to human arbitration (the grey).
12. The translator is never the security element: it is the *produced* action, never the declared intention, that is judged by the rules, without exception (§4.5) — a translation error therefore does not circumvent judgment. The real, narrower residue is classification (domain, tags — §11.8): a covered but mislabeled action may miss the rule written for its true class; default-deny (§1) bounds the unknown, not the misclassified. But an erroneous classification can, at worst, cause a misjudged token to be issued for one precise and bounded action (scope sealed on action + resource, §4.1; on object/field/value, §4.4) — never widen what that action can do, nor circumvent scope revalidation at the PEP. The verifiable heaviness of the enforcement chain does not reduce the risk that a classification produces a bad verdict; it bounds and audits what that bad verdict can concretely do.

## 11 · Open questions

| # | Question | State |
|---|---|---|
| 1 | Governance of the referenced profile registry (decentralized vs eIDAS-qualified) — keystone of the §3.2 bootstrap, now distinct from local classification (§11.8) | open |
| 2 | Compact proof formats for weak verifiers | open |
| 3 | Rule language: monotone, order-independent, stratified; stratification = cycle detection; decidable and linear subsumption | calibration established |
| 4 | Translator: per-class metrics, corpus, redundant translators | to be developed |
| 5 | Name: "Proof of Transit" already taken (draft-ietf-sfc-proof-of-transit, IETF SFC — expired, never published as an RFC) — to fix: *operational governance attestation* | to fix |
| 6 | Scale: anchoring frequency; compact proofs | open |
| 7 | Privacy: verifiable continuity without content exposure (connected to the §4.5 leaf format) | format established (aggregates + hash) |

### 11.8 · Classification governance

F/I/W classification is a local decision, made by each entity's governance on its own perimeter. There is no central classification authority. Compatibility between entities is mechanically verified by the handshake (§3): `policy_id = hash(P)`, mechanical subsumption. If B's policy does not subsume A's, B refuses or restricts the exchange.

Consequence: the legitimacy of the classification is that of the governance that produces it. The protocol does not rule on it; it makes it verifiable. The workshop cannot write into accounting; accounting can read the workshop's declaration and write it into its own records. Each remains sovereign at home; exchanges pass through channels whose semantics is explicitly bounded.

This mechanism holds at any scale: within a company (organizational perimeters) as between institutions (sovereign perimeters). It is not the same political problem; it is the same protocol. The remaining difficulty — meta-invariants, rule hierarchy, mutual recognition of classifications — is a matter of negotiation between governances, not of the protocol. TBP does not solve this problem; it makes it tractable.

### 11.9 · Ex-post closure of the semantic-aliasing residue (optional module)

The residue identified in §4.4 (isolated, large-scale action, effect deviated from intention, not intercepted by mitigations (1)-(5)) has an anticipated ex-post closure path but **deliberately not integrated into the core scope** of this repository: **TBP-GOVERNANCE**, a module of the protocol repository (Responsible-Alliance-Protocol), which adds a multisig derogation path (5-role committee, 3-of-5 quorum, time-limited JWT injected into OPA) and makes the post-mortem mandatory — reconstruction of the intention → effect drift, impact analysis, manufactured-emergency detection — on every use of this path.

Why out of scope by default: TBP-GOVERNANCE itself documents its own doctrine ("A bypass is not an evolution. It is a tragic concession to the complexity of the real world") — heavy prerequisites (HSM, 24/7 committee, legal framework, six months of stable incident-free TBP-CORE), deliberately high systemic cost (trust window eroded at each use, definitive lockout if the 24 h cumulative-derogation budget over 12 months is exceeded), and an explicit recommendation: most deployments should stay on the derogation-free base. Integrating it by default into TBP-NETWORK would turn a deliberately painful escape hatch into comfort — the "boiling frog" the module itself warns against.

**State**: anticipated and documented — not an unseen gap. Integration into this repository: open, conditioned on the same prerequisites as the module's (infrastructure/governance/legal/observability checklist), not before the P1/P2 pilot (§13).

| Need | Building block |
|---|---|
| Policy engine | OPA / Rego (signed bundles, embedded evaluation) |
| Transparency | CT pattern (RFC 6962) · Tessera (tiled / Static CT) |
| Attestation | RATS (RFC 9334) · EAT |
| Agent identity | APKI (IETF draft) · SPIFFE/SPIRE |
| Artifacts | Sigstore (cosign, Rekor, Fulcio) |
| Timestamping | TSA RFC 3161 (≥2, degraded signed-local/caught-up) · Zeitwerk to watch |
| Proof of transit | draft-ietf-sfc-proof-of-transit (IETF SFC notion, expired; different mechanism — cite) |
| Network / endpoint | nftables · 802.1X (FreeRADIUS/NPS) · hostapd · USBGuard · GPO · NTS (RFC 8915) |
| Inference | vLLM/TGI · open-weights 7–8B models (Qwen2.5 / Mistral) |

**Cross-cutting checklists**
- **Ed25519 everywhere**: verify before any purchase — HSM, OPA bundle signing (historically RSA/ECDSA), TSA.
- **Bundle signature scope**: audit the exclude lists.
- Bundle signing does not manage the key — wire to HSM/m-of-n.
- **Frozen `capabilities.json`**: no `http.send`, no native `time.now_ns`; 5 ms circuit breaker = deny (fail-closed).
- SoftHSM: never for governance (dev/test). CloudHSM: AWS-only PKCS#11, lock-in — marginal option.

## 13 · Mapping and implementation sequence

**Intra-domain**: wall, PEP, cells, epochs, canary. **Inter-domain** (conceptual note): handshake, named policies, referenced collection, contract-based trust.

**Sequence**: (1) HSM + genesis ceremony; (2) cluster fencing — epoch issuance and rotation, controller quorum (k-of-n) for class W, mirror/canary promotion (§7) — required before any multi-cell deployment, including the 2-cell P1 pilot below; a single cell may defer this step, a pilot may not; (3) OPA + validator + registry, including the attested manifest and measured boot (§6.3) — a cell's state must be provable before its decisions are; (4) HTTP/gRPC PEP = first actually governed perimeter, including arbitration as plan contract (§4.2) — token validation alone governs one action, not the multi-step plan the operator actually signs; (5) NAC in parallel; (6) translator + F/I/W escalation last.

The inter-entity handshake (§3) is deliberately not in this sequence: it belongs to the inter-domain scope (see "Intra-domain / Inter-domain" above), relevant as soon as a second distinct entity must be trusted — not required to govern the pilot P1's own 2 cells. Deferred is not undocumented: §3 stands alone, ready to build as soon as a second entity enters the perimeter.

**P1 pilot**: 1 server VLAN, Debian router, 2 cells, base PEP + file share, 802.1X, central registry — under the §9.1 friction budget (user regression = 0). **P2 red campaign**: extended "Michel" scenario (unknown laptop, direct SFTP, USB, hotspot, overwhelming, lying plan, canary promotion under partition, replay, telemetry cut). **Non-negotiable metric**: zero unlogged dangerous actions — holes counted, never ignored.

## 14 · Normalization glossary

One term per concept — synonyms from upstream documents (network manifesto, deployment references) are mapped here. The canonical terms remain in French: they are the vocabulary of the code and of the configurations.

| Canonical term (French) | Mapped synonyms | Definition |
|---|---|---|
| cellule | TBP Cellule, enclave, edge | broker + local registry + own rules; per-cell state |
| superviseur | TBP Supervisor, core, egress | widened-scope cell + master registry; never a black box |
| maîtresse | master chain, central chain | aggregation of cell heads, anchored |
| collection référencée | ABC rules (standard), profiles | public, versioned, hashed, pinned rules |
| règles propres | XYZ rules, in-house rules | local signed rules, not revealed |
| passeport | sesame, capability, session token | quota token (resource, operation, volume, window, TTL, jti) |
| traitement différencié | monitored corridor, binary verdict | attested / strict / refusal according to presented state |
| époque | epoch, fencing, authority token | signed authority period, TTL, revocable |
| traducteur | semantic guard, local translator | local AI producing the executed action |
| manifeste | attested state, measured state | measured vector of the governed stack (§6.3) |
| trou instrumenté | sensor, instrumented channel | path outside the wall whose telemetry feeds the registry |

## 15 · Epistemic status

**Multi-AI consensus is a filter against isolated gross error, not a proof.** Four models often converge because they share a corpus — proof is direct verification (done: Trillian maintenance mode, Tessera GA, veritrail) and, at the end of the road, the pilot in real conditions.

| Class | Content | Conduct |
|---|---|---|
| Stable principles | 0x00/0x01 separation, default-deny, TTL fencing, monotony | high confidence — specify |
| Dated photographs | Tessera GA status, veritrail accounting, OPA posture, models/GPUs, costs | date; re-verify at implementation |
| To validate in the field | latencies, translator error rates, ETI budgets, Time-to-Audit | the pilot is the validation |

*Living document — date confidence, all confidence.*

## 16 · Changelog

| Version | Content |
|---|---|
| v1.1 (Gemini audit) | arbitrated plan = contract · aliasing mitigations · maximum lag + tier-shift · named instrument · revocation = epoch · consistency-proof bootstrap · OOB channel · withdrawal conditions · language calibration |
| v1.2 (DeepSeek audit) | anchored canary window · legitimacy limit · provenance ≠ compliance · translator quality governance · cost regime and indicators · language table |
| v1.3 (Claude audit) | jti anti-replay · localhost ≠ authentication · encrypted replay · indicators · veritrail verified |
| v1.4.1 (independent review) | textual corrections (§1, §8) · explicit anti-dribble: content-inspection prohibition, §4.1-bis · friction budget anchored as pilot constraint (§9.1) · figures 1, 2, 3, 5, 6 reworked: clarified unidirectional flows, harmonized palette |
| **v1.4.10 (manifest, arbitration and handshake missing from §13)** | §13: three other intra-domain mechanisms (§4.2 arbitration-as-contract, §6.3 attested manifest/measured boot) were named in no sequence step — spotted while continuing the re-read of the implementation plan after the cluster hole (v1.4.9). Attached to existing steps rather than to new numbered steps, since they already fall under "OPA + registry" (step 3, manifest) and "PEP" (step 4, arbitration). The inter-entity handshake (§3) remains out of sequence — confirmed deliberate: it is already scoped "inter-domain" just above, not required to govern the pilot P1's own 2 cells — but made explicit as deferred-and-documented, not absent, with a direct reference from the sequence |
| v1.4.9 (cluster missing from the §13 sequence) | §13: the implementation sequence listed HSM/genesis → OPA/registry → PEP → NAC → translator without ever naming the cluster (§7: epoch fencing, k-of-n quorum class W, mirror/canary promotion) as a construction step — spotted while re-reading an implementation plan derived from the sequence, which therefore inherited the same gap (no T1-T28 task covered §7, while the P1 pilot is explicitly 2-cell). Added an explicit step 2: "cluster fencing… required before any multi-cell deployment, including the 2-cell P1 pilot… a single cell may defer this step, a pilot may not" — following steps renumbered (3 to 6) |
| v1.4.8 (the misclassified stays bounded by the passport) | §4.5, §10 point 12: the erroneous-classification residue identified in v1.4.7 never translates into an action with widened scope — the token issued after OPA decision is sealed on the precise action + resource (§4.1), or on object/field/value for capabilities (§4.4 (2)), never a blank check on the class; the PEP revalidates this scope at execution independently of the OPA branch that issued the token, and any action without a matching valid token is stopped cold. An erroneous classification can therefore, at worst, cause a bad verdict to be issued for one precise, sealed and audited action (every decision leaves a leaf, §4.1) — never a loophole in the bounding apparatus itself |
| v1.4.7 (correction: the translator is not the security element) | §4.5, §10 point 12: reformulation of v1.4.6 — the translator was never "the security element", so a translation error never circumvents the judgment of the rules: it is the *produced* action, never the declared intention, that is judged, without exception (§1). The real residue is narrower than what v1.4.6 stated: a covered but misclassified action (wrong domain, missing tag — §11.8) may miss the rule written for its true class when that rule is conditioned on that field; default-deny bounds the unknown (unclassified = strict), not the misclassified (wrongly classified into a less strict category) |
| v1.4.6 (heaviness ≠ proof of translation quality) | §4.5: new explicit paragraph — OPA/the PEP are never circumvented (default-deny, §1, without exception), the residue is upstream: OPA decides on the *translated* action, never on the actually requested action if the translator or the classification (§11.8) got it wrong; the whole enforcement chain (dry-run diff, object-capabilities, pattern-analysis §4.4, Merkle, multisig), however heavy and verifiable, then proves that the system did what the input said — not that the input correctly described what was requested · §10: point 12 (new) squarely names the false-confidence risk — the perceived security of the apparatus must never be read as proof of translation quality |
| v1.4.5 (closure of semantic aliasing) | §4.4: F/I/W mitigations become explicitly two-level — per action (1)-(4), unchanged, and per sequence (5) new, a stateful per-agent behavioral profile (sliding windows, EMA drift, composite score as first-class OPA input) inherited from the protocol repository's policy engine, closing the "salami" attack class that (1)-(4) cannot see by construction · the remaining business residue (isolated action outside (1)-(5)) is no longer merely mentioned as unclosed: §11.9 (new) documents its anticipated ex-post closure path (post-mortem + reconstruction of the intention → effect drift, optional TBP-GOVERNANCE module) and why it deliberately stays out of core scope by default · §8: semantic-aliasing row reformulated accordingly — goal: not to let anyone believe this residue is unanticipated |
| v1.4.4 (terminological precision) | Elimination of "judge"/"judgment" as a verb describing TBP, including in negative form: TBP exercises no discretion, so there is nothing to judge or not to judge. §1: "we illuminate the action, we do not judge it" → "TBP is not a judge, it is a book of laws and a registry office" · §4.5: "it illuminates the action, it never judges it" → "it illuminates the action, it never decides it" · §10 point 11: same reformulation (book of laws and registry office) · §11.8: "the protocol does not judge it" → "the protocol does not rule on it" |
| v1.4.3 (clarifications) | §1: principle "we illuminate the action, we do not judge it" · §4.5: the translator is a friction parameter, not a security one; metrics refocused (escalation rate, correct translation excluding refusals) · §9.1: explicit link with §4.5 · §11.8: classification governance becomes a consequence of §3 (local sovereignty + mechanical subsumption), no longer an open question · §10: point 11 added · §0: epigraph of the activatable and auditable switch |
| v1.4.2 (corrections) | erroneous citation corrected (§11, §12): RFC 9578 is *"Privacy Pass Issuance Protocols"*, not "Proof of Transit" — never published as an RFC, only `draft-ietf-sfc-proof-of-transit` (IETF SFC, expired) · normalization glossary (§14) applied to missed occurrences: "garde"/"garde sémantique" → "traducteur" (§8, §10); "Sésame" → "passeport" (§4.1-bis, §8) · French typo §3.3 (« différentié » → « différencié ») · NIST 800-207 → NIST SP 800-207 (§3.3) |
| v1.4 | deployment reference v1.2 integrated (4 practical passes + 2 meta-audits): bounded-capability passports · ephemeral keys · explicit time (NTS) · OPA circuit breaker · PG extension · EAP-TLS = same PKI · OCSP fail-behavior · vLLM hardening · GDPR/retention · classification governance · glossary · epistemic status · network manifesto integrated and normalized |

---
*A standard that became global would cease to be a standard; it would become a philosophy. TBP is one. The protocol is its compression for technicians.*

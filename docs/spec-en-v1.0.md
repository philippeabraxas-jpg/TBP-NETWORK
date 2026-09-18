# TBP — Attested Action Governance
## Specification v1.0 (English) · 17 September 2026 · Philippe Collet

> *Existing access control decides whether you enter; TBP decides what you may do once inside — and proves it. We govern capabilities, not models.*
> *Free to think. Bounded to act. Provably.*

---

## 0 · Evidence status

This document is a specification, not an implementation report. The evidence behind it comes in three classes:

- **Running** — the TBP core protocol (repository `Responsible-Alliance-Protocol`, v4.2.1): working implementation, unit tests, live public demo (invarian.fr), and an independent adversarial review process (Appendix A).
- **Specified** — this document: the network deployment architecture (TBP-NETWORK), passports, clusters, epochs, registry.
- **Planned** — TBP-NETWORK code and test suites (build order in §13), the first translator corpus, the P1 pilot and P2 red-team campaign.

Claims in this document are assigned to one of these three classes throughout. Targets are labeled as targets; mechanisms that exist only as specifications are labeled as such. Nothing here is presented as measured that has not been measured.

![Figure 1 — The TBP governance chain](figs/fig1_chaine.png)

## 1 · Doctrine

- **Never by trust, always by verifiable proof** — every claim (identity, rules, transit, decision) is a cryptographic property, not a statement.
- **Never by name, always by signature** — a name can be copied; a signature over (object, time, scope) cannot.
- **Never by yes, always by default-deny** — the unknown is classified strict (including APIs without declared invariants).
- **Defeatable but detectable** — we never claim "impossible"; we claim "impossible to conceal" *within the governed path*.
- **We govern capabilities, not machines** — the question is not "can one enter without passing the router" (always yes) but "what can one reach" (bounded) and "who will see it" (proven).
- **System invariants** — non-derogable prohibitions: control can never be removed from the designated human controller; no surveillance or monitoring beyond declared telemetry without express authorization.
- **TBP is not a judge; it is a book of laws and a clerk** — it mechanically applies rules written by the business; no discretion is exercised at execution. It produces a three-position state: denied (rule or translator), authorized (nothing in TBP prevents it), submitted (grey — the only admitted discretion, and it is human).
- **The executed action is the translated action** — the translator produces the action; an agent's lie about its intent never propagates to the effect.
- **A lied decision remains attributable** — a compromised component can lie about the decision, not about its responsibility.
- **We do not close every hole; we rank holes by impact and mitigate proportionally** — governance is allocation, not completeness. Bricks do not make a house's architecture; what matters is the coherence of the ecosystem — built, wherever possible, on mature bricks.

## 2 · Threat model

**Attackers**: malicious or hijacked agents; unmanaged machines introduced on the network; insiders; and an attacker able to down, **isolate**, replace, or **flood** components — including by controlling **timing** (delays, partitions, windows).

**Not preventable (detectable)**: hotspot/4G traffic, local models, physical access to an unmanaged machine.

**Trust base** (declared): governance keys (HSM, m-of-n); at least one independent monitor; an authenticated out-of-band channel for genesis keys and controllers; the telemetry instrumentation itself (§5.3 — a sensor held by the attacker stops sensing; this is admitted, not hidden).

## 3 · Inter-entity handshake

The handshake proves three things: **(1) under which rules the entity operates** (`policy_id = hash(P)`, mechanical subsumption over a constrained rule language); **(2) that its history is continuous** (O(log n) consistency proof; every change is a signed transition event; unexplained discontinuity = corruption = refusal); **(3) that it is operational at the instant of exchange** (verifier nonce through the real cycle — OPA evaluation, registry leaf, HSM signature; targets accept only in-flight-issued tokens).

**Bidirectional subsumption for class W.** Classes F and I remain under local classification sovereignty. For class W (survival — actions whose blast radius crosses perimeters), subsumption runs **in both directions**: a W action must satisfy *both* perimeters' W rules. The strictest common denominator is not negotiated; it is **computed** by cross-subsumption. Each side carries the other's right of inspection on W.

### 3.2 · Bootstrap: genesis, late joiners, legitimacy limit

Epoch 0 is signed by the controller quorum and externally anchored at genesis. A late joiner verifies the key chain (out-of-band), an O(log n) consistency proof, and transition continuity. **Explicit limit**: the bootstrap proves non-alteration, not legitimacy — a parallel-genesis attack (TOFU) passes all consistency checks; legitimacy comes from a referenced registry (eIDAS-type, lightweight local PKI, or consortium-backed depending on scale), outside the protocol.

### 3.3 · Differentiated treatment

| Presented state | Treatment |
|---|---|
| Attested, subsuming policy | throughput calibrated to classification |
| Unattested / unknown | strict tier: side effects blocked or arbitrated, bounded egress |
| Unexplained discontinuity | refusal + monitor alarm |

**Positioning**: TBP is neither NAC, nor Zero Trust (NIST SP 800-207), nor entity authentication (PKI, APKI, SPIFFE). It adds: action semantics, the human-arbitration tier, third-party-verifiable proof.

## 4 · Action governance (machine level)

### 4.1 · Mechanism and tiers

A signed token (Ed25519, 30–60 s TTL, scope = action + resource, unique `jti`) is issued after OPA evaluation; a local **PEP** validates signature, freshness, scope, and non-consumption. Three tiers: **harmless** (read-only) → direct execution, sub-ms; **to arbitrate** (side effect) → human validation; **out of scope** → immediate refusal with rewording proposal. Classes F (financial), I (infrastructure), W (survival) escalate requirements (§5.3); undeclared = W.

### 4.1-bis · Quota-bound passports (data plane)

Any heavy path opening (session, tunnel, SDN rule) is issued as a **quota-bound passport**: a token extending the action token with a quota vector `(resource, operation, volume_max, window, TTL, jti)` — cryptographically bound and signed, never in an out-of-band modifiable rule.

- **Counter at execution** (PEP / terminator): decrements volume; lightweight, TTL-bounded data-plane state — one terminator per session. Exceed → clean cut + refusal + registry leaf.
- **Egress envelope at issuance** (broker): per-entity, per-epoch aggregate quota evaluated by OPA at issuance — closes aggregation of legitimate passports.
- **Flow-metadata telemetry**: bytes per interval, destination, rhythm (NetFlow/IPFIX-style — **content inspection of passport flows is proscribed**, it would destroy the data-plane speed gain): anti-dribble relies exclusively on metadata post-treatment (dribble, sub-threshold exfiltration). Metadata leaves feed the registry like decision leaves.
- **Doctrine**: prevent what is cheap, detect what is expensive — every opened door is born with its counter and its instrument (§5.3).

![Figure 5 — Quota-bound passport](figs/fig5_passeport.png)

### 4.2 · Arbitration is a signature, not a reading

The plan shown to the operator is generated by the agent (probabilistic) and could lie (benign abstract plan masking a destructive path). The approved plan is a **contract**: execution is verified against the hash of the approved plan; deviation = refusal. **Scope of the defense**: the contract alone binds *consistency*, not *intent*; intent is addressed jointly with the dry-run diff (§4.4(1)) — only the pair (contract + observed effect) addresses a plan that misdescribes itself. Residual for non-transactional actions (no dry-run possible) is declared in §4.4.

### 4.3 · Anti-replay

Signature + freshness + scope answer nothing about "already consumed?". Each PEP keeps a consumed-token cache bounded by the token TTL — the same architectural pattern as the passport's execution-time counter (§4.1-bis). Replay is bounded to N reachable PEP replicas per TTL window (a named parameter, growing with load); F/W classes are additionally closed by service-side idempotency. Every execution leaf carries the `jti`; replay is detectable in post-treatment everywhere, prevented at the PEP.

### 4.4 · Order–effect gap (semantic aliasing)

Effect integrity belongs to the business. The PEP validates the envelope, not hidden effects (triggers, cascades). Mitigations, bounded to classes F/I/W, operate on **two levels**:

*By action*: (1) dry-run with diff-of-state submitted to OPA before commit; (2) object-capabilities (token sealed to object/field/value hashes); (3) in-process PEP — for PostgreSQL, **two hooks are required, not one**: `post_parse_analyze_hook` for structural validation (which tables, which operation) against the parse tree — needed because `ExecutorStart` alone is post-planning, a volatile side-effect function can already have been evaluated by the time it fires — **and** `ExecutorStart_hook`, immediately before execution, validating a sealed hash of the *finalized* plan including bound parameter values. `post_parse_analyze` alone is insufficient on its own for a different reason: it fires once, at parse time, so an extended-query-protocol prepared statement (`PREPARE ...; EXECUTE ... ($1, $2)` — the default behavior of connection poolers and ORMs) is validated once against placeholders, and every subsequent `EXECUTE` with concrete bound values skips it entirely; (4) contract-driven — an API without declared post-conditions is classed W.

*By sequence*: (5) stateful behavioral profile per agent (sliding 24 h/7 d windows, cumulative amounts and counts, burst frequency, EMA drift, temporal anomaly), composite score versioned as a first-class OPA input — never an out-of-policy heuristic. Closes by construction the salami class (N sub-threshold actions, aggregate above-threshold effect) that (1)–(4) cannot see.

**Declared residual**: a single, large, isolated action whose effect deviates from intent and passes (1)–(5) remains possible (the business residual, §10.5). Its closure path is ex-post and deliberately outside this core's default scope: mandatory post-mortem with intention→drift reconstruction, recalibrating F/I/W thresholds (optional TBP-GOVERNANCE module). It is documented, anticipated — not an unseen gap.

### 4.5 · The translator: structural anti-fraud, measured quality

**Doctrine**: the executed action is the action *translated* by the local semantic guard — an agent's lie about its intent never propagates to the effect. The translator is a **friction parameter, not a safety parameter**: it never decides whether an action is safe — the produced action is judged by the rules without exception (default-deny). It says "I can translate" or "I cannot". Its quality determines the escalation rate and hence the tenability of the friction budget (§9.1); it does not determine safety, which is carried by the rules, the quorum (§7.5), and human arbitration.

**Two stages**: a low-latency, low-cost **scorer** for closed classification classes (confidence output maps directly to escalation: low confidence → strict tier) and an LLM for open decomposition and reformulation. Dual classification (two independent models; disagreement → strictest tier) is an optional, documented defense-in-depth brick — with its cost (2× inference, escalation rate) — not core. A narrower residual remains: a *covered but mislabeled* action (wrong domain, missing tag) can miss the rule written for its true class when that rule is conditioned on the field; default-deny bounds the unknown, not the mislabeled. A mislabel cannot, at worst, do worse than a wrongly-judged verdict on a *precise, sealed, audited* action (scope sealed to action + resource, §4.1; to object/field/value for capabilities, §4.4(2)); the PEP re-validates scope independently of the OPA branch that issued the token. A wrong classification cannot widen what an action can do. A mislabel does not corrupt the judgment: only the produced action is judged, and the produced action is what executes. A mislabeled action that the fired rules judge harmless executes as judged — wrong, perhaps, but not unjudged; if it is dangerous *as produced*, it is denied like any other. A mislabel can only skip class-conditioned controls — a rule keyed on the wrong field, or mandatory arbitration — and in the dangerous case that reduces to the general rules-quality residual (§4.4, §10.5), not to a property of the label. What mislabeling costs is quality and friction; the seal and the default-deny bound everything else.

**Quality governance**: differentiated precision per class; native-language corpora, positive and negative; shadow mode; continuous measurement (corpus replay at each update + human sampling). Design targets — FNR < 0.1 %, FPR < 2 % — are **per-class engineering targets for friction optimization, to be validated** on the first native corpus at pilot; no translator-metric leaves exist in the registry yet, and the registry defines the leaf format (aggregates + corpus hash; content never in clear). A scorer of the Jev class (decision models answering typed Choice/Score questions with confidence, without token generation — e.g. TypeSafe's Jev, launched 15 September 2026) is the emerging candidate for the classification stage. Vendor claims are days old, calibration is not independently validated, and quality trails frontier models on vendor-reported evaluations — it is recorded here as a dated photograph (§15), not a foundation. The architecture it embodies — *the model supplies semantic judgment and does not own the policy* — converges with this specification's doctrine; that convergence is the signal, not any single vendor.

**Degraded modes & fallback** — network-level, per scale:
- **Critical systems**: failover to a **mirror cell** (§7.4), which continues under pre-established governance rules (deterministic path) — the cluster's mirrors exist for this.
- **Standard systems**: automatic escalation to **human arbitration**.
- **Neither available**: immediate **default-deny**.
- No cloud fallback of any kind: the translator is local by doctrine (§4.5).
- **Translator threshold breach / Failure**:
  1. For **sensitive/critical systems**: execution falls back to **pre-established governance decision rules** (deterministic fallback) with direct transfer to a **system clone / mirror environment**.
  2. For **standard systems**: automatic escalation to **human arbitration**.
  3. If neither is available or applicable: immediate **default-deny**.
- No unverified cloud fallback is permitted.

**Runtime hardening** (vLLM/PyTorch): dedicated non-root user, CAP_DROP_ALL, strict seccomp — dm-verity protects the image at rest, not the runtime surface.

## 5 · Enterprise network architecture

### 5.1 · The wall and the steering

No direct client → server path; the server accepts only the broker. NAC is **steering**: authenticated (802.1X, EAP-TLS) → VLAN giving access to the broker; unknown → **captive VLAN** whose only route is enrolment or broker-forced governance. EAP-TLS reuses **the same PKI as the handshake** — one identity infrastructure for network admission and application attestation. L2 anti-detour: strict server VLAN, DHCP snooping + DAI, AP isolation.

![Figure 3 — Network topology](figs/fig3_reseau.png)

### 5.2 · Catalogue of off-router paths

| Path | Closed by | Residual / compensation |
|---|---|---|
| East-west machine→machine | switch ACLs, AP isolation, host firewalls | same-VLAN → strict segmentation |
| Hardware (USB, Thunderbolt) | USBGuard, GPO, BIOS/IOMMU | endpoint, not network |
| Hotspot / 4G | — (unclosable) | resource PEPs · instrumented |
| Local model | — | we do not govern the brain |
| Console / iLO / admin | mgmt VLAN, jump hosts, logged acts | admin = most audited entity |
| Unregistered machine | NAC → broker-forced / captive VLAN | — |

### 5.3 · Doctrine of holes

> *An uninstrumented hole in the wall is a door. An instrumented hole is a sensor.*

"Instrumented" requires a **named instrument**: host telemetry (file integrity, logs, flow metadata) **fed to the registry**. A channel without an instrument leaves acts unprevented and unseen — the only forbidden state. Concealment is impossible for acts within the governed path; acts entirely outside any instrumented perimeter are covered by detection only, and the instrumentation itself is in the trust base (§2).

| Class | Examples | Requirement |
|---|---|---|
| F — financial | payment, ERP write | PEP token + arbitration + quota |
| I — infrastructure | prod, CI/CD | PEP token + strict scoping |
| W — survival | mass effect | PEP + arbitration + quorum (§7.5) + §4.4 + cross-perimeter subsumption (§3) |
| outside F/I/W | reading, internet | wall + audit (conditions 1 or 3) |

- **Telemetry is a class-W action**: cutting it — even by an administrator under pressure — requires a quorum; it is signed, alarmed, and recorded.
- **Factory defaults**: the default "RADIUS unreachable" behavior is often fail-open — force fail-closed per switch. Unreachable OCSP/CRL → remediation VLAN with feedback, never blind soft-fail.
- **Deployment**: monitor mode before closed mode; no RADIUS-assigned VLAN in v1; MAB = instrumented channel (dedicated IoT VLAN, never silent).

## 6 · Registry: two-level architecture

Each cell keeps its own chain (sessions, batches) — hot path without coordination. Periodically, `hash(broker_id, head, TSA)` from each cell is inscribed in the **master chain** (CT pattern, RFC 6962). Engine: **Tessera** (GA library, POSIX driver — one directory = one cell log); bootstrapping: veritrail (test against RFC 6962 vectors); Rekor/cosign = the **artifacts** registry (§1), never decisions. A full homebrew is ruled out: leaf/node domain separation is the most publicly audited part of the ecosystem — and a proof verifiable by a third party loses its value if the auditor must re-read your code. Ecosystem signal: Let's Encrypt is migrating its RFC 6962 logs to the Static CT / tiled API — Tessera's direction is the field's direction.

![Figure 4 — Two-level registry](figs/fig4_registre.png)

### 6.2 · Temperatures — and explicit time

| Path | Role | Tolerated failures |
|---|---|---|
| Hot: broker + OPA + HSM | decision, token | N+1 stateless, failover in seconds |
| Warm: registries | recording, sequencing | replicated, idempotent |
| Cold: anchoring + monitors | external proof, detection | third-party, store-and-forward |

- **Bounded lag**: the epoch token carries the last anchor's hash; the PEP refuses tokens whose anchoring exceeds a bound (default 120 s). Flooding yields denial of service, never an impunity window. Complement: dynamic tier-shift under load.
- **Time is an explicit founding assumption**: TTLs, epochs, TSA, and freshness all inherit a strict clock-synchronization assumption. Requirement: **NTS (RFC 8915)** on brokers/PEPs; skew and freshness bounds are **parameters** with declared fail-closed behavior on excess (skew > bound → freshness refused immediately). The deferred-TSA catch-up window (sign locally when the TSA is unreachable, anchor later) is **strictly bounded by the depth of the last verified external anchor** — fork-rewrite beyond it is detectable by construction.
- **GDPR / retention**: an infinite append-only log conflicts with retention obligations — hash-only leaves, salting, explicit retention policy.

### 6.3 · Attested state = manifest

`(policy_id, OPA config, broker hash, local AI container hash, chain head)` — every component change is a visible, signed, continuous transition; the hash is that of the signed package (§1). Measured boot: the node's root is measured by the TPM/HSM at startup.

## 7 · Cluster: cells, epochs, mirrors, canary

### 7.1 · Cattle, not root of trust

The broker is not the root of trust; keys and the master chain are. States are per cell; the system's state lives in the master chain plus the current epoch. The Supervisor is a cell with widened scope plus the master registry — same mechanics, same doctrine, never a new black box.

### 7.2 · Epoch fencing

Epoch token `(N, authority, ~60 s TTL)` signed by controllers (m-of-n, HSM); only the holder serves; the previous expires by itself — two authorities impossible by construction. Manual failover: controllers reachable on a separate channel. Pre-authorized automatic failover ("max N flips/hour, then human"); 3 cells + 2-of-3 majority for failover under isolation.

### 7.3 · Revocation = new epoch

A compromised cell: epoch with reduced roster; its tokens die; **quarantine, not murder** — the frozen cell serves the analysis.

### 7.4 · Mirrors and canary — anchored window

Bundle hash anchored per epoch (`policy_id` = rules hash = the handshake hash). The healthy window is **defined and anchored in the master chain — never measured by the canary itself** (a network attacker can isolate it during measurement); promotion = proof of receipt of the anchored bundle. An eligible cell satisfies all externally committed requirements.

### 7.5 · Quorum

Class-W actions: k-of-n co-signature; a single cell, adversarial or captured, cannot authorize the maximal irreversible.

### 7.6 · Intra-epoch compromise — provenance ≠ conformity

During an epoch's TTL, a component holding its local keys can issue allow tokens the policy would not have authorized. What remains proven: attribution (*it can lie about the decision, not about its responsibility*), the time bound (TTL, then revocation), W protection (quorum), the impossibility of rewriting the past. **Explicit trade-off**: local OPA makes this fraud possible; remote co-evaluation would close it at latency cost — configurable per class (default: local for tier 1, co-evaluation for F and W).

### 7.7 · Policy evolution (contract agility)

Verifiable monotonicity (§11); legitimate weakening = motivated transition, visible, updating verifiers' consent; negotiated workflow without downtime or window; historically continuous compliance.

![Figure 6 — Key and time hierarchy](figs/fig6_cles.png)

## 8 · Threats ↔ mechanisms

| Threat | Mechanism | Residual |
|---|---|---|
| Multilingual prompt injection | deterministic floor + translator + output auditor | interception < 100 % (bounded) |
| Description fraud (lying agent) | translator: the executed action is the translated action | structurally closed |
| Translation error | rules (default-deny) + measured quality (§4.5) | bounded quality damage (friction) |
| Abstract-plan lie in arbitration | contract + dry-run diff (the pair, §4.2) | — for transactional; declared for non-transactional |
| Semantic aliasing | business-primary + §4.4 by action and by sequence (F/I/W) | business residual; ex-post closure anticipated (optional module) |
| Token replay | jti + PEP cache + F/W cardinality | bounded to N replicas; detectable |
| Open tunnel (passport) | quota passport + envelope + metadata (§4.1-bis) | dribble → post-treatment |
| Local PEP bypass | service re-validation / peer credentials / eBPF cgroup | — |
| Unmanaged machine | NAC steering; wall; resource PEPs | hotspot/local model: detection |
| Broker down / adversarial | stateless N+1; fencing; pinned keys | alarmed DoS — never an act |
| Split-brain | epoch TTLs; 2-of-3; OOB controllers | — |
| Registry flooding | bounded lag + tier-shift | DoS — never impunity |
| Canary promotion under partition | anchored window + receipt proof | — |
| Intra-epoch cell compromise | TTL + revocation + W quorum | attributable acts, post-facto detection |
| Governance key theft | m-of-n; HSM; quorum | future signable, past sealed |
| Poisoned bundle | signature + anchored canary | limited canary window |
| Parallel genesis (TOFU) | — (assumed) | legitimacy = referenced registry (§3) |
| Admin under pressure (telemetry cut) | telemetry = W action (quorum, alarm) | root trust assumed elsewhere |
| Death by friction | bounded F/I/W perimeter + indicators (§9) | operational risk n°1 |

## 9 · Real cost and exit conditions

Target latencies: tier 1 < 2–5 ms; tier 2: 10–50 ms; tier W: seconds to minutes. **The cost regime changes**: from a rare, catastrophic cost (the act) to a continuous, visible cost (governance). Prevented acts are invisible; daily frictions are visible.

**Three exit scenarios**: (A) break-glass — disengagement is a governed act; (B) death by friction (most likely) — counter: govern strictly F/I/W; (C) DoS cascade — price: assumed loss of provability.

**Decision threshold**: maintain TBP iff P(irreversible act) × cost(act) > cost(DoS) + cost(friction).

**Time-to-Audit** (< 1 week vs 3–6 months): a commercial metric — its proof chain (measured baseline, ETI-scale validation) is to be built before client-facing use.

### 9.1 · Friction budget — founding constraint of the pilot

The architecture is usable *because it accepts being imperfect*; this constraint is a measurable requirement, not an intention:

- **Added tier-1 latency < 5 ms** (deterministic floor, continuously measured).
- **Human arbitration target < 10 % of actions** (beyond: governance becomes the bottleneck — §9 indicator). This rate is directly a function of translator quality (§4.5): the translator is the main tuning lever of the friction budget.
- **Pilot failure condition: measured user-experience regression = 0** — protection must never be paid in blocked legitimate tasks.
- **Failure direction**: the system fails toward denial, never toward silent approval; the organizational bypass risk is declared in §9(B).

## 10 · What the system does not claim

1. Not 100 % secure — **100 % auditable on a declared perimeter**.
2. The translator is probabilistic; the guarantee is the floor.
3. Attestation commits to the rules, not their perfect execution.
4. The hotspot / local-model channel is incompressible.
5. The real effect of an action remains the business's responsibility.
6. Intra-epoch fraud is possible and bounded (§7.6).
7. Genesis legitimacy is not provable by the protocol (TOFU; referenced registry required).
8. The root admin remains a trusted actor — the most audited.
9. Availability has a price.
10. Compliance (EU AI Act art. 14) is the entry price of human arbitration; TBP amortizes it.
11. TBP is not a judge; it is a book of laws and a clerk — it makes action governable, signed, auditable; safety verdicts belong to business rules and human arbitration.
12. The translator is never the security element (§4.5): only the produced action is judged, never the declared intent. Mislabeling is a quality and friction risk, not a judgment bypass: a mislabel cannot produce an unjudged action — the produced action is judged without exception — and cannot widen what an action can do; at most it skips class-conditioned controls (arbitration, field-keyed rules), which in the dangerous case is the general rules-quality residual (§10.5), declared and bounded.

## 11 · Open questions

| # | Question | Status |
|---|---|---|
| 1 | Governance of the referenced rule registry — the protocol is scale-agnostic: **it prepares the architecture that enables scale-dependent application decisions**. Deployment choice maps to scale (locally pinned keys for a single organization; eIDAS/TSL-qualified registries for national regulated entities; consortium-backed anchors for cross-sovereign federations). Open at every scale: who curates the collection two governances will reference together (§3) — for W-class, cross-subsumption computes the floor; the curation negotiation is out of protocol scope | scale-mapped; curation open |
| 2 | Compact proof formats for low-resource verifiers | open |
| 3 | Constrained rule language: monotone, order-independent, stratified; stratification = cycle detection; subsumption decidable and linear. **Fine-tuning rules re-draws perimeters — a governance act, hence constrained by the determinism profile** (§12); a policy that breaks the profile is rejected by CI | calibration set |
| 4 | Translator: per-class metrics, corpora, redundant translators | to develop |
| 5 | Naming: "proof of transit" is taken only as an expired IETF SFC draft (never an RFC; RFC 9578 is Privacy Pass) — fix the term: *operational governance attestation* | to fix |
| 6 | Scale: anchor frequency; compact proofs | open |
| 7 | Privacy: continuity verifiable without content exposure (bound to the §4.5 leaf format) | format set (aggregates + hash) |

**11.8 · Classification governance.** F/I/W classification is a local decision, made by each entity's governance over its own perimeter; there is no central classification authority. Cross-entity compatibility is verified mechanically by the handshake (§3): `policy_id = hash(P)`, mechanical subsumption. If B's policy does not subsume A's, B refuses or restricts. Consequence: the legitimacy of a classification is that of the governance producing it; the protocol does not rule on it, it makes it verifiable. The workshop cannot write to accounting; accounting can read the workshop's declarations and write them to its own registers. Each remains sovereign at home; exchanges flow through channels whose semantics are explicitly declared. This mechanism holds at every scale — organizational perimeters and sovereign perimeters — **with the W-class exception of §3: on survival-class actions, each side carries the other's inspection right, by bidirectional subsumption**. The remaining difficulty — meta-invariants, rule hierarchy, mutual recognition of classifications — belongs to negotiation between governances, not to the protocol. TBP does not solve that problem; it makes it visible, and for W it computes the floor.

## 12 · Reused bricks and checklists

| Need | Brick |
|---|---|
| Policy engine | OPA / Rego (signed bundles, embedded evaluation) |
| Transparency | CT pattern (RFC 6962) · Tessera (tiled / Static CT) |
| Attestation | RATS (RFC 9334) · EAT |
| Agent identity | APKI (IETF draft) · SPIFFE/SPIRE |
| Artifacts | Sigstore (cosign, Rekor, Fulcio) |
| Timestamping | TSA RFC 3161 (≥ 2, deferred sign-local/catch-up) · Zeitwerk (EU federation) to watch |
| Proof of transit | IETF SFC proof-of-transit (expired draft; never an RFC; distinct mechanism — cite as precedent concept only) |
| Network / endpoint | nftables · 802.1X (FreeRADIUS/NPS) · hostapd · USBGuard · GPO · NTS (RFC 8915) |
| Inference | vLLM/TGI · open-weights 7–8B (Qwen2.5 / Mistral) · decision scorers (Jev-class, §4.5) |

**Cross-cutting checklists**
- **Ed25519 everywhere**: verify before any purchase — HSMs, OPA bundle signing (historically RSA/ECDSA-centered), TSA mechanisms.
- **Bundle signature scope**: audit exclude lists (signatures do not automatically cover all files).
- Bundle signature does not manage the key — wire to the HSM / m-of-n.
- **`capabilities.json` frozen**: no `http.send`, no native `time.now_ns` (timestamp injected via input); circuit-breaker 5 ms = deny (fail-closed).
- **Determinism profile** (§11.3): ordered constructs only (lists, sorted keys); no aggregations whose result depends on iteration order; CI order-stability test — K identical evaluations must produce identical outputs.
- SoftHSM: never governance (dev/test). CloudHSM: AWS-only PKCS#11, non-exportable keys (lock-in) — marginal option.

## 13 · Mapping and implementation sequence

**Intra-domain**: wall, PEPs, cells, epochs, canary. **Inter-domain** (companion concept note): handshake, named policies, referenced collection, trust by contract.

**Sequence**: (1) HSM + genesis ceremony — nothing is signable before; (2) cluster fencing — epoch issuance and rotation, controller quorum (k-of-n) for class W, mirror/canary promotion (§7) — required before any multi-cell deployment, including the 2-cell P1 pilot below; a single cell can defer this, a pilot cannot; (3) OPA + stratification validator + base registry, including the attested manifest and measured boot (§6.3) — a cell's own state must be provable before its decisions are; (4) HTTP/gRPC PEP = first truly governed perimeter, including plan-as-contract arbitration (§4.2) — token validation alone governs a single action, not the multi-step plan an operator actually signs; (5) NAC in parallel (monitor phase starts early — calendar time); (6) translator + F/I/W escalation (PG proxy, co-evaluation, 70B/MoE) last.

The inter-entity handshake (§3) is deliberately not in this sequence: it is inter-domain scope (see "Intra-domain / Inter-domain" above), relevant once a second, distinct entity needs to be trusted — not required to bring the P1 pilot's own 2 cells under governance. Deferred is not the same as undocumented: §3 stands on its own, ready to build when a second entity is in scope.

**Pilot P1**: one server VLAN, Debian router, 2 cells, DB + share PEPs, 802.1X, central registry — under the §9.1 friction budget (user regression = 0). **P2 red-team campaign**: the extended "Michel" scenario (unknown laptop, direct SFTP, USB, hotspot, flooding, lying plan, canary promotion under partition, replay, telemetry cut). **Non-negotiable metric**: zero dangerous action unlogged — holes counted, never ignored.

**Stability policy**: this specification is versioned conservatively; changes pass through signed, attested transitions (the registry's own chain is the changelog).

## 14 · Normalization glossary

One term per concept — upstream synonyms (network manifest, deployment references) are mapped here.

| Canonical | Mapped synonyms | Definition |
|---|---|---|
| cell | TBP Cell, enclave, edge | broker + local registry + own policies; state per cell |
| supervisor | TBP Supervisor, core, egress | cell with widened scope + master registry; never a black box |
| master chain | master chain, central chain | aggregation of cell heads, anchored |
| referenced collection | rules ABC (standard), profiles | public, versioned, hashed, pinned rules |
| own rules | rules XYZ, house rules | local signed rules, unrevealed |
| passport | sesame, capability, session token | quota token (resource, operation, volume, window, TTL, jti) |
| differentiated treatment | guarded corridor, binary verdict | attested / strict / refused per presented state |
| epoch | epoch, fencing, authority token | signed authority period, TTL, revocable |
| translator | semantic guard, local translator | local AI producing the executed action |
| manifest | attested state, measured state | measured vector of the governed stack (§6.3) |
| instrumented hole | sensor, instrumented channel | off-wall path whose telemetry feeds the registry |

## 15 · Epistemic status

**Multi-AI consensus is a filter against isolated gross error, not proof.** Multiple models often converge because they share a corpus — proof is direct verification (performed: Trillian maintenance mode, Tessera GA, veritrail existence) and, at the end of the road, the pilot in real conditions.

| Class | Content | Handling |
|---|---|---|
| Stable principles | 0x00/0x01 domain separation, default-deny, TTL fencing, monotonicity | high confidence — specify |
| Dated photographs | Tessera's GA status, veritrail's accounting, OPA posture, models/GPU, costs, Jev-class scorers | date them; re-verify at implementation |
| To validate in the field | latencies, translator error rates, ETI budgets, Time-to-Audit | the pilot is the validation |

*Living document — date all confidence, all of it.*

---

## Appendix A · Review process

This specification was developed through a documented adversarial process: multiple independent AI evaluators were interrogated **in contradiction**, with different prompts and different sessions, each tasked to attack the design (find the scenario that breaks it) rather than to approve it. The working loop: a human poses the problem; machines explore the solution space; the human judges the results; findings are archived and dated.

This process is a **method for arbitrating design points quickly — not a validation and not proof**. Its known limits are stated in §15: evaluators share training corpora (correlated errors possible); they do not replace field validation (the pilot); and the strongest evidence remains the artifact itself — the code that runs, the demo, the dated reports. Reviewers named in the working records: Gemini, DeepSeek, Claude. Their value here is the disagreement they were made to produce.

---

*A standard that became global would cease to be a standard; it would become a philosophy. TBP is one. The protocol is its compression for technicians.*

*First result of the working document: this specification.*

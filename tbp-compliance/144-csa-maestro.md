# CSA MAESTRO (7-layer agentic threat model)

**Status: Full**
**Source**: [issue #144](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/144)
**Reference**: [CSA MAESTRO](https://github.com/CloudSecurityAlliance/MAESTRO) (Multi-Agent Environment, Security, Threat, Risk, and Outcome), Cloud Security Alliance
**Last verified**: 2026-09-29

## Scope note

MAESTRO is not a numbered checklist like AST10 or the LLM Top 10 — it's a layered reference architecture, where each layer has "traditional" threats (inherent to the tech, agent-independent) and "agentic" threats (new or worsened by non-determinism, autonomy, absent trust boundaries). Table below: one row per layer, not per control. Sources: the original CSA paper was unreachable during research (cloudsecurityalliance.org / labs.snyk.io blocked); layer names/definitions confirmed via a web-research synthesis citing the CSA blog — worth revalidating against the full paper if direct access becomes available.

Legend: ✅ Covered · 🔴 Real gap (needs code; the row links the issue that tracks it) · ⚪ Not TBP's concern (the row says why and, for a deployment, how to close it). A combined status splits one control between what TBP covers and what stays with the deployer. See the [catalogue README](README.md).

## The 7 layers vs. TBP

| Layer | What MAESTRO covers | Status | Detail |
|---|---|---|---|
| **L1 — Foundation Models** | Pre-trained/fine-tuned LLM, base reasoning | ⚪ | Entirely out of scope — TBP never sees the model itself, only the structured `Translation` a translator produces from its output. |
| **L2 — Data Operations** | Data pipelines, labeling, storage | ⚪ | Out of scope — no training data ever transits TBP. Not to be confused with TBP's audit chain (§6.2), which stores hash-only DECISIONS, not training data. |
| **L3 — Agent Frameworks** | Orchestration and decision-making between agents | ✅ | The broker already orchestrates the DECISION CHAIN (translator→OPA→quorum→contract→envelope→emission, §5.1) for one agent at a time. Per-threat status: agent identity spoofing → ✅ closed by `AgentRegistry` (#125); **tool misuse → ✅** closed by `SkillRegistry` (#165, PR #166) — an action matching no registered skill, or targeting a resource outside its declared scope, is refused before OPA evaluation (`skill-unknown`/`skill-scope-violation`); insecure inter-agent communication → ✅ structurally inapplicable, the "no direct client → server path" doctrine forbids any agent-to-agent channel outside broker mediation; unauthorized delegation → ✅ each hop is judged alone: a delegate's request is evaluated against the delegate's own class, scope and skills, so delegation never transfers the delegator's rights, and "who may ask whom" is expressible in Rego on `input.subject` (`tbp.pack.agent_scope`); `ContractStore` bounds execution to a pre-sealed plan. **Not modelled:** a delegation chain as a first-class object. **To close:** write the permitted A→B pairs in Rego and require class W for any delegated irreversible act. |
| **L4 — Deployment & Infrastructure** | Containerized/cloud hosting | ⚪ | TBP is not a container orchestrator (out of scope by construction), but the project documents a real deployment topology: VLAN segmentation, 802.1X/EAP-TLS NAC (`deploy/router-debian.md`), one VM per cell (`deploy/cellule.md`) — treated as a documented DEPLOYMENT PREREQUISITE, never a TBP runtime feature. **To close:** apply the deployment prerequisites (`deploy/router-debian.md`, `deploy/cellule.md`) and run `deploy/verify_network_isolation.sh` from the agent's network context at each deployment (`deploy/network-isolation.md`, [#186](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/186)): it checks that the allowed proxy is reachable, that arbitrary outbound TCP fails, and that the nftables rules are loaded and active — TCP only, state at run time. |
| **L5 — Evaluation & Observability** | Monitoring, system integrity | ✅ | Exactly `src/supervision` (T34) + the tessera audit chain (master chain, anchoring §6.2): `KindTelemetry`, `KindAnchor`, `KindSupervision`, the timed monitor and read-only console — a substantial, purpose-built observability layer. |
| **L6 — Security & Compliance** | Privacy, access control, regulatory assurance | ✅ | Access control → ✅ strong (OPA + `AgentRegistry`); privacy → ✅ strong (hash-only leaves, §6.2 — see [GDPR](155-gdpr.md)); formal regulatory assurance → this whole `tbp-compliance/` series is the answer to what used to be a total void here. |
| **L7 — Agent Ecosystem** | Multi-agent collaboration with external systems | ⚪ product scope | TBP's cell/cluster model (fencing, quorum, epoch authority — T29) is a real multi-entity trust model, but it's CELL-to-CELL federation (brokers talking to each other), not open agent-to-agent discovery/interaction across organizational boundaries (agent marketplaces etc.) that this layer seems to target at CSA. Not resolved as a technical gap — it's a product-scope question: should TBP ever extend beyond inter-cell federation? **To close:** nothing is required unless your deployment federates across organizations; then the inter-entity handshake ([#33](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/33)) and the encrypted inter-cell transport ([#187](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/187)) are the prerequisites. |

---

## Summary

**Where TBP is already strong, unnamed**: L5 (observability) and half of L6 (access control + privacy) are substantially covered by mechanisms built for other reasons (§4.1, §6.2, #125).

**Structurally non-applicable, not an oversight**: L1, L2 — out of scope by construction, TBP was never meant to touch the model or its training data.

**Closed since the original catalog**: L3's "tool misuse" sub-point, by `SkillRegistry` (#165, PR #166) — the third confirmation (after [#142](142-owasp-agentic-skills-top10.md), [#143](143-owasp-llm-top10.md)) that this was the right priority.

**Left open, a product decision, not a code gap**: L7 (agent ecosystem) — whether TBP should ever reason beyond inter-cell federation is a scope question, not a fix.

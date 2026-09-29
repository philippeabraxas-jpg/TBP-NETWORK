# OWASP GenAI LLM Top 10 (2026)

**Status: Partial**
**Source**: [issue #143](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/143) · fix: [issue #168 / PR #169](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/168) (Unicode instruction-smuggling)
**Reference**: [OWASP GenAI LLM Top 10 2026](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final) (LLM01–LLM10)
**Last verified**: 2026-09-29

## Scope note

This framework covers the full LLM lifecycle — training, RAG, embeddings, output rendering — while TBP intervenes at exactly ONE point in the chain: after a translator has produced a structured `Translation` (action/resource/class), before a token is issued. Many LLM risks (training-data poisoning, RAG, embeddings) are therefore structurally upstream of TBP — not an oversight, just not the right component for that layer.

Legend: ✅ Covered · 🟡 Partial · 🔴 Real gap, new broker plumbing needed · 🟢 Real gap, implementable in Rego today · ⚪ Out of TBP's scope

## LLM01:2026 Prompt Injection

| # | OWASP mitigation | Status | Detail |
|---|---|---|---|
| 1 | Constrain model role via system prompt + privilege controls | ⚪ | Upstream of TBP — TBP doesn't control the system prompt. |
| 2 | Strict output schema, validated in trusted application code before action | ✅ | Exactly `StructuredTranslator` + `dec.DisallowUnknownFields()` (`server.go`) — no action reaches OPA without strict structural validation. |
| 3 | Filter at every modality boundary | ⚪ | TBP receives already-extracted text/JSON, never raw multimodal input. |
| 4 | Credentials/state-change capability in trusted app code, never in the model; deterministic policy-engine routing with runtime re-validation | ✅ | Exactly the broker architecture: Issuer/HSM are never exposed to the model, every action re-passes through OPA (deterministic, §1). |
| 5 | Strip invisible-instruction-smuggling characters (Unicode zero-width, variation selectors) at ingestion | ✅ | **Fixed.** `rejectSmugglingUnicode` (`broker.go`) rejects `Action`/`Resource`/`Quota.Resource`/`Quota.Operation` containing zero-width chars (U+200B–200F), directional overrides (U+202A–202E), word-joiner/invisible operators (U+2060–2064), variation selectors (U+FE00–0F, U+E0100–E01EF), a BOM (U+FEFF), or ASCII-smuggling tag characters (U+E0000–E007F) — a fail-closed `translation-failed` refusal, never a silent strip (#168, PR #169). |
| 6 | Structurally separate, provenance-labeled channels for data vs. instructions | ✅ | `Translation{Action, Resource, Class, …}` *is* that separate channel — raw intent never reaches OPA as-is. |
| 7 | Explicit human confirmation before privileged/irreversible actions, showing the exact rendered action | 🔴 | The cryptographic mechanism exists (`QuorumGate`, class W, k-of-n); displaying "the exact rendered action" to the operator is console tooling not yet built. The approval channel itself exists (admin-socket plan submit/approve, #177) and the class-W quorum is enforced; **what is missing is the operator console that renders the exact translated action before someone signs.** Tracked in the admin-tooling work, [#86](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/86). |
| 8 | "Rule of Two": untrusted input + sensitive data + simultaneous state change = per-action review | ⚪ | Class W already triggers a per-action quorum, but the class is a static registry value (#125), not dynamically derived from this three-factor heuristic. **Why grey:** TBP sees a structured intent, not where the model's inputs came from, so it cannot tell untrusted input from trusted; the class is a registry value on purpose (#125). **To close:** register as class W (plan + quorum per action) every agent that both ingests untrusted content and can change state on sensitive data, and keep such agents' skills at `risk_tier` high/critical so the `tbp.pack.skill_tier` gate applies too. Sequences of individually harmless actions are [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181). |
| 9 | Treat agent memory writes as privileged, log/classify, require approval before persistence | ✅ files · ⚪ other backends | **File-based agent memory is covered:** writes to `SOUL.md`/`MEMORY.md`/`AGENTS.md` are refused below class W (plan approval + quorum) by `tbp.pack.agent_hardening` (`policies/rego/pack_agent_hardening.rego`); see [#142](142-owasp-agentic-skills-top10.md) AST01.6. **Other memory backends** (vector stores, cloud memory services) are covered only if their resource names are added to `extra_protected_files` — TBP cannot know them. *Deployer action:* list every persistent-memory resource of your agents in that bundle-data key. |
| 10 | Pin/sign/verify MCP servers and third-party tools, audit descriptions | ✅ pinning · ⚪ signing | `SkillRegistry` (#165, PR #166) now pins provenance/scope of each skill out-of-band — pinning satisfied; cryptographic signing and automated description auditing remain to be built. **To close:** verify each MCP server's signature or digest in your installation pipeline before adding it, record the digest in `provenance`, and review its tool descriptions when you set its `scope` and `risk_tier` — TBP never reads tool descriptions. |
| 11 | Test against adaptive attackers | ⚪ | Test process, not runtime. |

## LLM02:2026 Sensitive Information Disclosure

Largely out of scope: this risk covers training, RAG and model observability — TBP never sees weights, training data, or generation context.

| Mitigation | Status | Detail |
|---|---|---|
| Log/trace scrubbing, technical non-retention policy | ✅ | Exactly the hash-only leaf doctrine (§6.2): the salt stays with the producer, no leaf ever carries business content — a structural "no-retain," not a bolted-on policy. |
| Rate-limit sensitive requests per user/session | ✅ | `EnvelopeLedger` (§4.1-bis) already caps volume/window per subject — generalizable to a resource classified "sensitive." Per agent and per window, with the quota resolved by the registry. A per-resource rate limit is part of the sequence profile tracked in [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181). |
| Everything else (differential privacy, confidential computing, re-identification testing, training-data governance) | ⚪ | TBP is not a training/model-serving platform — structurally upstream. |

## LLM03:2026 Excessive Agency

The risk closest to TBP's actual purpose.

| Mitigation | Status | Detail |
|---|---|---|
| Limit tools/functions to the strict minimum, granular input schemas | ✅ | **Closed by the per-agent allowlist:** rule pack `tbp.pack.agent_scope` (`policies/rego/pack_agent_scope.rego`) lists, in the signed bundle data, the exact actions (and resources) each agent may ask for; with `require_agent_scope` an agent without an entry is refused. Combined with the skill registry (each skill's own exact scope) this is the "strict minimum" at two levels. Tested and mutation-checked in `policies/tests/pack_agent_scope_test.rego`. |
| Limit permissions granted to other systems to the minimum | ✅ · ⚪ downstream | TBP bounds what an agent may *target* (`agent_scope` resources, skill `scope`). **Why the rest is grey:** the permissions an executor holds on the other systems live in those systems, not in TBP. **To close:** grant each executor's credential only the rights its skill's `scope` needs, on the target side (see AST 3.5 in [#142](142-owasp-agentic-skills-top10.md)). |
| Trace user authorization/scope so the action executes in the right context | ✅ | `subject` flows through the whole chain (`OPAInput.Subject`, Issuer claim, `AgentRegistry` resolution) — exactly the point closed by #125. |
| Human-in-the-loop for high-impact actions | ✅ | `QuorumGate`, class W (§7.5). |
| Policy/logic-engine authorization, never model decision | ✅ | Central broker doctrine (§1) — OPA judges, the model only proposes a translation. |
| Monitor downstream tool/system activity | 🔴 | `BrokerStats` + `KindDecision` leaves trace everything, but no anomalous-pattern detection. Tracked by [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181) (behavioural profile by sequence). |
| Thresholds and circuit breakers on tool invocation | ✅ | Dual real mechanism: the 5ms fail-closed OPA circuit-breaker (T11) AND the `EnvelopeLedger` volume/window cap. |

## LLM04:2026 Supply Chain

Strongly overlaps AST02/AST04/AST10 already catalogued in [#142](142-owasp-agentic-skills-top10.md) (signing, SBOM, verified sources). The LLM-specific angle (vetting third-party models/datasets, AIBOM/ML-BOM, edge-device attestation) is ⚪ out of scope — TBP receives intent from a model already chosen upstream; it never selects or vets that model itself. No separate tracking line here.

## LLM05:2026 Data and Model Poisoning

Entirely ⚪ out of scope: training/fine-tuning/RAG-pipeline poisoning — TBP has no visibility into the model's learning process or its data.

## LLM06:2026 Unbounded Consumption

| Mitigation | Status | Detail |
|---|---|---|
| Rate limiting beyond RPS (tokens/minute, tokens/day, cost per request) | ⚪ | **Why grey:** LLM tokens and their cost are consumed at the model gateway, which TBP does not see; TBP caps the *actions* an agent may take (`EnvelopeLedger`, per subject and window). **To close:** set per-key token and cost caps in the model gateway or LLM proxy in front of the agent. The action-level cost signal is [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181). |
| Hard, non-bypassable spend caps per key/user/team/account | ✅ | Exactly `AgentQuotaPolicy.MaxVolume/MaxWindowS` (#125) — cap resolved by the broker, never the caller's self-declared value. |
| Dynamic resource-allocation management | ⚪ | **Why grey (deliberate):** `EnvelopeLedger` has fixed, bounded capacity; saturation refuses (fail-closed) rather than evicting, so an attacker cannot push a legitimate entry out. **To close:** size capacity before deployment (scale guides, [#86](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/86)) and alert on saturation. |
| Sandboxing of network/internal-service access | ⚪ | OS/network isolation, outside the execution policy layer. |
| Graceful degradation under load | ⚪ | The OPA circuit-breaker degrades to a total refusal (fail-closed), not partial functionality — a deliberate security choice (§1), not a NOT "graceful" degradation in the OWASP sense. **To close:** decide per service that "closed" is acceptable, and where it is not, run redundant cells (deployment guides, [#86](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/86)) rather than a permissive fallback. |
| Queue limits, dynamic scaling | ⚪ | Infra/scaling, outside TBP. |
| Detect abnormally costly tool-invocation patterns | 🔴 | No anomaly detection of this kind today. **Tracked by [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181)** — the by-sequence behavioural profile already *specified* in spec §4.4(5) (sliding windows, cumulative amounts, burst frequency, EMA drift), not yet implemented. Same work closes the salami / decomposition class. |
| Agentic circuit breakers: step limits, recursion depth, time limit, per-run cost cap | ✅ steps and time · 🔴 per-run cost | `ContractStore.MaxPlanSteps=64` (T30) bounds the number of steps of a plan; plans are flat sealed step lists, so there is no recursion to bound; the time limit is the token lifetime (30–60 s) and the plan's `expires_at`. **Not covered:** a per-run cost cap (the quota is per time window, not per plan execution) — part of [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181). |
| Inference-infrastructure hardening | ⚪ | That's the model server, not TBP. |

## LLM07:2026 Misinformation

| Mitigation | Status | Detail |
|---|---|---|
| Anchor outputs in trusted sources | ⚪ | TBP neither generates nor fact-checks content. |
| Separate generation from execution via verification checkpoints | ✅ | The founding doctrine (§4.5): "the action executed is the translated action," never the model's raw claim. |
| Validate tool calls for authorization/preconditions | ✅ | OPA (authorization) + `ContractStore` (precondition: the step must match the sealed plan). |
| Grounding checks rather than confidence score alone | ⚪ | N/A — TBP does binary policy conformance, a stricter standard than a confidence score. |
| Approval workflows for high-impact actions | ✅ | `QuorumGate` again. |
| Structured outputs with required fields to prevent omission | ✅ | `structuredIntent` requires `action`/`resource`, fail-closed refusal if absent. |
| Limit damage via least-privilege/sandboxing | ✅ least privilege · ⚪ sandbox | Least privilege is enforced at three levels: class and quota per agent (#125), exact `scope` and `risk_tier` per skill, and the per-agent allowlist (`tbp.pack.agent_scope`). **Why the sandbox is grey:** execution stays outside TBP (§4.5). **To close:** confine the executor as described in [#180](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/180) and verify network isolation with [#186](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/186). |
| Log results, trace claims/evidence | ✅ | `KindDecision` leaves. |
| Calibrate confidence between verified facts and assumptions | ⚪ | Outside TBP's layer. |
| Continuous adversarial testing | ⚪ | Process. |

## LLM08:2026 Hidden Context Exposure

| Mitigation | Status | Detail |
|---|---|---|
| Never put secrets/critical config in the model's hidden context | ✅ | Hash-only doctrine (§6.2) applied systematically — nothing sensitive is ever embedded in what TBP stores or forwards. |
| Model-independent deterministic controls rather than hidden context as a control mechanism | ✅ | Exactly the broker principle: OPA/quorum/contract are ALWAYS external and deterministic, never a prompt instruction. |
| Authorization and access control enforced independently of the LLM | ✅ | Same — "no discretion" (§1), class/quota come from the registry (#125), never the model. |

Three mitigations out of three already covered — TBP is structurally well-positioned here precisely because it has always refused to trust the model's own declaration.

## LLM09:2026 Vector and Embedding Weaknesses

Entirely ⚪ out of scope: TBP has no vector database, RAG, or embeddings anywhere in the code.

## LLM10:2026 Improper Output Handling

Largely ⚪ out of scope: TBP never renders or forwards LLM-generated free text to an execution sink (HTML/JS/SQL/shell) — it processes an already-STRUCTURED intent and emits a signed token in a fixed binary format (CWT/COSE_Sign1, hex). No injection surface of this kind by construction.

---

## Summary

**Overlaps with [#142](142-owasp-agentic-skills-top10.md) (AST10)**: LLM01.9/10 (agent memory, third-party tools) and LLM04 (supply chain) point to the same `SkillRegistry`.

**Gap found here and fixed**: LLM01.5 — Unicode canonicalization (zero-width, variation selectors, BOM, tag characters) on `Action`/`Resource`/`Quota` before OPA evaluation, in `StructuredTranslator` (#168, PR #169).

**Narrowed by the agent-hardening rule pack**: LLM01.9 (agent memory writes) — file-based memory now needs class W; other backends need their names listed (see row 9).

**Still open (needs code)**: operator console that renders the exact translated action before approval (LLM06 human confirmation) — [#86](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/86); downstream-activity monitoring, cost-anomaly detection and a per-run cost cap (LLM06/LLM10) — [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181).

**Closed by rule packs**: per-agent tool and permission allowlist (`tbp.pack.agent_scope`, LLM06), file-based agent memory (`tbp.pack.agent_hardening`, LLM04 n°9). **Grey, with a deployer action in each row**: Rule of Two, MCP signing, token/cost caps at the model gateway, capacity sizing, sandboxing of the executor.

**Where TBP is already strong, unnamed**: LLM03 (Excessive Agency), LLM06 (Unbounded Consumption), LLM07 (Misinformation) and LLM08 (Hidden Context Exposure) — the translator→OPA→quorum→quota architecture *is* OWASP's recommended mitigation for half this top 10, designed independently of it.

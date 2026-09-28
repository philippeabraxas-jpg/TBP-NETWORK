# OWASP Agentic Skills Top 10 (AST10)

**Status: Partial**
**Source**: [issue #142](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/142) (analysis) · [issue #165 / PR #166](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165) (SkillRegistry fix)
**Reference**: [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (AST01–AST10, 2026 checklist)
**Last verified**: 2026-09-28

## Scope note

AST10 describes a **supply chain problem for installable skills** (packages distributed via registries like ClawHub/skills.sh). Before this analysis, TBP had no notion of "skill" at all — its scope was authorizing an *action* of an already-equipped agent (`broker.HandleAction`), not admitting a new capability into that agent. Most of the gaps below trace back to that one missing layer, closed (in part) by `SkillRegistry` (#165, PR #166) on the same pattern as `AgentRegistry` (#125).

Legend: ✅ Covered · 🟡 Partial (mechanism exists elsewhere in TBP, needs replicating) · 🔴 Real gap requiring new broker plumbing · 🟢 Real gap, implementable as a Rego rule today, no new Go code · ⚪ Out of TBP's scope

## AST01 — Malicious Skills (CRITICAL)

| # | Control | Status | Detail |
|---|---|---|---|
| 1.1 | Verify publisher identity, reject typosquatting | 🟡 | `SkillRecord.Provenance` documents the source, verified out-of-band at genesis (#165) — same pattern as `AgentRegistry`. |
| 1.2 | Behavioral/intent scanning | ⚪ | External scanner/CI concern, not a policy-engine role. |
| 1.3 | Ed25519 signature + manifest `content_hash` | 🟡 | The crypto mechanism exists (`Issuer`/`DevSigner`/`PKCS11Signer`, `ContractStore` already verifies Ed25519 operator signatures on plans) — never yet applied to a skill manifest. |
| 1.4 | Manual code review | ⚪ | Human process, not runtime. |
| 1.5 | Isolated canary rollout | ⚪ | CI/deployment concern. |
| 1.6 | Forbid writes to `SOUL.md`/`MEMORY.md`/`AGENTS.md` without explicit justification | 🟢 | **Implementable today**: a `deny` rule matching `resource` against these names — `Resource` is already a free string carried by `StructuredTranslator`, no new plumbing. Not yet written. |

## AST02 — Supply Chain Compromise (CRITICAL)

| # | Control | Status | Detail |
|---|---|---|---|
| 2.1 | Bind publisher to a verified signing key | 🟡 | Documentary provenance is real (`SkillRecord.Provenance`); no cryptographic per-skill signature yet. |
| 2.2 | Pin the version to an immutable SHA-256 hash, reject ranges | ✅ | Pattern replicated from `AgentRegistry`/`OperatorKeys`/genesis controllers: out-of-band table, never resolved dynamically, no runtime mutation path. |
| 2.3 | Lock transitive dependencies to hashes | ⚪ | Build-time, outside TBP runtime. |
| 2.4 | SBOM (CycloneDX/SPDX) | ⚪ | CI tooling — see [SCVS](157-owasp-scvs.md) for TBP's own SBOM. |
| 2.5 | Treat repo config files (`hooks`, `.claude/settings.json`) as executable code | 🟡 | Same principle as the devmode doctrine (#113): a single file, without an independent second signal, must never be able to disarm a protection. Applies in theory; nothing enforces it for skill hooks yet. |
| 2.6 | Recursive dependency-tree scanning | ⚪ | CI tooling. |
| 2.7 | Pre-mutation receipt before any write | 🔴 | The concept exists for actions (`writeLeaf` before token emission, §4.1) — never for skill installation, which has no notion of "install." |

## AST03 — Over-Privileged Skills (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 3.1 / 3.2 | Explicit, bounded permission manifest; minimize to real needs | ✅ | `SkillRecord.Scope` — exact literal comparison, never a prefix; an unregistered action carries zero privilege. |
| 3.3 | `shell:false` or command allowlist | 🟢/🟡 | Implementable as a Rego rule if `Action`/`Resource` already encode the command — otherwise 🟡 (a dedicated field is missing). Not yet written. |
| 3.4 | Explicit file paths, never broad globs | 🟢/🟡 | Same remark as 3.3. |
| 3.5 | Isolate credentials per skill, scheduled rotation | 🔴 | `Scope` bounds targeted *resources*, not per-skill credentials — TBP has no per-skill credential concept at all; not covered by SkillRegistry. |
| 3.6 | Flag `SOUL.md`/`MEMORY.md` writes for elevated review | 🟢 | Duplicate of 1.6 — same quick-win. |
| 3.7 | Network permissions as a domain allowlist, default-deny egress | 🟢 | Implementable today: a Rego rule parsing the domain from `Resource` (already a URL in HTTP cases) against a configurable allowlist. Not yet written. |
| 3.8 | Block access to credential stores/`.env`/wallets/SSH/browser data | 🟢 | Same family as 1.6/3.6 — quick-win Rego rule on known `resource` patterns. Not yet written. |

## AST04 — Insecure Metadata (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 4.1 | Description ↔ actual functionality match | ⚪ | Semantic analysis, not runtime. |
| 4.2 | ASCII-smuggling / zero-width / base64 scanning | ⚪ | Scanner concern — note the related but distinct fix in [OWASP LLM Top 10 LLM01.5](143-owasp-llm-top10.md) (Unicode instruction-smuggling on `Action`/`Resource`, already fixed). |
| 4.3 | Safe defaults, explicit opt-in for dangerous capabilities | 🟡 | Principle already applied everywhere (devmode #113: nothing dangerous is active without a flag + independent sentinel) — not yet replicated for a future skill manifest. |
| 4.4 / 4.9 / 4.11 | Schema validation, strict JSON-key allowlist, pre-deserialization validation | ✅ | `loadSkillRegistry` (brokerd/main.go) rejects any empty action, empty provenance, or empty table — same fail-closed discipline as the rest of the repo. |
| 4.5 | Cross-reference declared `risk_tier` against permission scope | 🔴 | `Scope` exists; `SkillRecord` has no `risk_tier` field yet. |
| 4.6 | Block brand impersonation | ⚪ | Process/branding, not runtime. |
| 4.7 | Safe YAML parser (`safe_load`) | ⚪ N/A | TBP is Go, no PyYAML — but the principle is present: `dec.DisallowUnknownFields()` in `server.go:handleAction` rejects any JSON smuggling. |
| 4.8 | Parse in an isolated subprocess | ⚪ | OS-level. |
| 4.10 | Sandbox dependency installation | ⚪ | OS-level/CI. |
| 4.12 | Drop privileges before parsing | ⚪ | OS-level. |

## AST05 — Untrusted External Instructions (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 5.1 | Inventory of referenced external URLs/docs | ✅ | `TBP_SKILL_REGISTRY_FILE` is this out-of-band inventory. |
| 5.2 | Pin each reference to a content hash | 🟡 | Same pattern as 2.2, not yet applied to external references specifically. |
| 5.3 | Prefer signed inlining over runtime fetch | 🔴 | Design decision for a future SkillRegistry extension. |
| 5.4 | Restrict runtime fetches to a domain allowlist | 🟢/🟡 | Same remark as 3.7. |
| 5.5 | Transitive review of the reference graph | ⚪ | Static analysis. |
| 5.6 | Fleet-wide visibility (which skill fetched which source) | 🟡 | Close to what the leaf registry already does (every decision traced, hash-only, §6.2) — a `KindSkillFetch` leaf type would be consistent with the 12 existing `Kind`s. |

## AST06 — Weak Isolation (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 6.1 | Isolated container/sandbox, never host-mode by default | ⚪ | TBP is not a container runtime — already explicit deployment-prerequisite territory (`deploy/router-debian.md`: network isolation, never execution isolation). |
| 6.2 | Limit filesystem access to declared paths | 🟢/🟡 | Same remark as 3.4. |
| 6.3 | Controlled network access, authenticated localhost bind (never bare `0.0.0.0`) | ✅ | Exactly what #124 closed for brokerd's data plane: mandatory mTLS, never plaintext TCP. Protects the broker, not a skill executed by the agent. |
| 6.4 | seccomp/AppArmor | ⚪ | OS-level, outside Go/TBP. |
| 6.5 | Inter-skill isolation (namespacing) | 🔴 | TBP never executes the action itself ("the action executed is the translated action", §4.5) — nothing to namespace broker-side; remains a property of the agent's own execution environment. |
| 6.6 | Rate-limit + authenticate WebSocket, even on localhost | ✅ | Unix-socket 0660 + `SO_PEERCRED` doctrine (`opa_transport.go`), now also mTLS (#124). |
| 6.7 | Restrict hot-reload in production | ✅ | Exactly #92.A5 (OPA bundle revision-check, refuse on mismatch) + devmode doctrine. |

## AST07 — Update Drift (MEDIUM)

| # | Control | Status | Detail |
|---|---|---|---|
| 7.1 | Pin to an immutable hash in the inventory | 🟡 | Pattern identical to `AgentRegistry`/`OperatorKeys`. |
| 7.2 | Disable auto-update / explicit re-approval in prod | ✅ | Exactly #92.A5 for the OPA bundle. |
| 7.3 | Cryptographic signature on every update | ✅ | Already done for the OPA bundle (§106, RSA signature verified by OPA itself). |
| 7.4 | Automatic re-scan on every version change | ⚪ | CI tooling. |
| 7.5 | Disable hot-reload outside dev | ✅ | Devmode doctrine (#113) + revision-check. |
| 7.6 | Subscribe to security advisories / CVE alerts | ⚪ | Organizational process. |

## AST08 — Poor Scanning (MEDIUM)

Almost entirely ⚪ out of TBP's scope — behavioral/semantic analysis, secret detection, multi-tool scan pipelines are CI/scanner territory; TBP must never claim to be a scanner. The one actionable point: require a `scan_status` field in a future skill manifest and `deny` if absent or stale (🟡, depends on SkillRegistry extension).

## AST09 — No Governance (MEDIUM)

| # | Control | Status | Detail |
|---|---|---|---|
| 9.1 | Centralized inventory (name, version, hash, date, installer, scan status) | 🟡 | TBP already has this reflex for other domains (`agents.json`/`operators.json`/`cells.json`) — replicate the pattern for skills, don't invent a new one. |
| 9.2 | Assign `risk_tier` consistent with scope | 🔴 | No `risk_tier` field in `SkillRecord` yet. |
| 9.3 | Approval registry (workflow, approver, date) | 🟡 | Close to `ContractStore` (T30): a signed Ed25519 operator approval, hash-sealed — exists for plans, not for skill admission. |
| 9.4 | Log invocations with sufficient audit detail | ✅ | Every decision already leaves a `KindDecision` leaf (§4.1), hash-only. |
| 9.5 | Review cadence based on risk_tier | ⚪ | Organizational process. |
| 9.6 | Formal revocation process | 🟡 | The concept exists (cell quarantine §7.3, plan revocation in `ContractStore`) — not wired to skills. |
| 9.7 | Agent identities as NHI, IAM, scheduled rotation | 🔴 (rotation only) | `AgentRegistry` (#125) closes agent *identity* (class/quota resolved, never self-declared); credential rotation is not automated (fixed seed/HSM key) — remains a real gap on this specific sub-point, outside SkillRegistry's scope. |

## AST10 — Cross-Platform Reuse (MEDIUM)

Almost entirely ⚪: TBP is a closed, single-architecture system by construction ("no direct client → server path") — the very notion of "same skill across multiple platforms" doesn't apply. The one live item: a **Universal Skill Format** for the manifest (🔴) becomes directly relevant if/when `SkillRecord` is extended further — worth basing any future schema on one close to what OWASP cites, to avoid a later migration.

---

## Summary

**Closed by SkillRegistry (#165, PR #166)**: publisher identity/provenance (1.1), version pinning pattern (2.2), permission scope (3.1/3.2), manifest schema validation (4.4/4.9/4.11), skill inventory (5.1), third-party supplier relationship gaps confirmed independently by [#144](144-csa-maestro.md), [#145](145-mitre-atlas.md), [#148](148-iso-iec-42001.md), [#152](152-iso-iec-27001-27002.md), [#153](153-nist-csf-800-53.md).

**Still open — Rego quick-wins, no new Go code needed**: 1.6/3.6 (forbid `SOUL.md`/`MEMORY.md`/`AGENTS.md` writes), 3.7/5.4 (network domain allowlist from `Resource`), 3.8 (block known credential-store paths), 3.3/3.4 (command/path allowlists, where the action already encodes them). None of these rules have been written yet.

**Still open — needs a `SkillRecord` extension**: per-skill credential isolation (3.5), `risk_tier` field (4.5, 9.2), scheduled credential rotation (9.7).

**Design note — can a SkillRegistry entry be modified?** No runtime mutation path exists for either an agent or a hot-reload; only an operator editing the out-of-band file and restarting `brokerd` can change a skill record. See [#165](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165) for the full design rationale.

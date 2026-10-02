# OWASP Agentic Skills Top 10 (AST10)

**Status: Full**
**Source**: [issue #142](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/142) (analysis) · [issue #165 / PR #166](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165) (SkillRegistry fix)
**Reference**: [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (AST01–AST10, 2026 checklist)
**Last verified**: 2026-09-29

## Scope note

AST10 describes a **supply chain problem for installable skills** (packages distributed via registries like ClawHub/skills.sh). Before this analysis, TBP had no notion of "skill" at all — its scope was authorizing an *action* of an already-equipped agent (`broker.HandleAction`), not admitting a new capability into that agent. Most of the gaps below trace back to that one missing layer, closed (in part) by `SkillRegistry` (#165, PR #166) on the same pattern as `AgentRegistry` (#125).

Legend: ✅ Covered · 🔴 Real gap (needs code; the row links the issue that tracks it) · ⚪ Not TBP's concern (the row says why and, for a deployment, how to close it). A combined status splits one control between what TBP covers and what stays with the deployer. See the [catalogue README](README.md).

**How to read ⚪.** A grey row is not "ignored": it is a control that belongs to another layer (the executor, the OS, the deployer's PKI, the change process). Every grey row that concerns a deployment says *why* it is grey and **what the deployer or operator does to close it** (prefixed **To close:**), so the catalogue stays usable as a deployment checklist. Rows that are grey only because they are a scanner or organizational concern carry a one-line reason.

## AST01 — Malicious Skills (CRITICAL)

| # | Control | Status | Detail |
|---|---|---|---|
| 1.1 | Verify publisher identity, reject typosquatting | ✅ | `SkillRecord.Provenance` documents the source, verified out-of-band when the entry is written (#165) — same pattern as `AgentRegistry`. **Typosquatting:** matching is exact and literal, so a look-alike action name is simply unregistered (`skill-unknown`). **To close (deployer):** verify the publisher before adding an entry and write down how in the change record (see 2.7). |
| 1.2 | Behavioral/intent scanning | ⚪ | External scanner/CI concern, not a policy-engine role. |
| 1.3 | Ed25519 signature + manifest `content_hash` | ⚪ | **Why grey:** TBP never loads or runs skill code, so there is no manifest for it to verify; its signature primitives serve tokens, plans and quorum. **To close:** verify each skill's Ed25519 signature and `content_hash` in your installation pipeline *before* adding it to the registry, and record `publisher@sha256:<hash>` in `provenance` so the audit shows what was admitted. |
| 1.4 | Manual code review | ⚪ | Human process, not runtime. |
| 1.5 | Isolated canary rollout | ⚪ | CI/deployment concern. |
| 1.6 | Forbid writes to `SOUL.md`/`MEMORY.md`/`AGENTS.md` without explicit justification | ✅ | Rule pack `tbp.pack.agent_hardening` (`policies/rego/pack_agent_hardening.rego`), violation `protected-agent-file`: a write/delete on these files is refused below **class W**. Class W *is* the explicit justification — an approved plan (#177) plus a k-of-n quorum (§7.5) — and the class comes from `AgentRegistry` (#125), never from the agent. More names via bundle data `extra_protected_files`. Tested in `policies/tests/pack_agent_hardening_test.rego` (mutation-checked) and run in CI (`opa test`). |

## AST02 — Supply Chain Compromise (CRITICAL)

| # | Control | Status | Detail |
|---|---|---|---|
| 2.1 | Bind publisher to a verified signing key | ⚪ | **Why grey:** same as 1.3 — a per-skill signature is checked where the skill is installed, not by TBP. Documentary provenance is real (`SkillRecord.Provenance`). **To close:** as 1.3, and keep the publisher's verification key in your own key inventory. |
| 2.2 | Pin the version to an immutable SHA-256 hash, reject ranges | ✅ | Pattern replicated from `AgentRegistry`/`OperatorKeys`/genesis controllers: out-of-band table, never resolved dynamically, no runtime mutation path. |
| 2.3 | Lock transitive dependencies to hashes | ⚪ | Build-time, outside TBP runtime. |
| 2.4 | SBOM (CycloneDX/SPDX) | ⚪ | CI tooling — see [SCVS](157-owasp-scvs.md) for TBP's own SBOM. |
| 2.5 | Treat repo config files (`hooks`, `.claude/settings.json`) as executable code | ⚪ | **Why grey:** TBP does not read the agent runtime's repo or config files; the principle applies to TBP itself and is enforced there (devmode #113: a single file, without an independent second signal, can never disarm a protection). **To close:** treat the runtime's hook and settings files as code — review, sign and deploy them like the registry (2.7), and mount them read-only for the agent. |
| 2.6 | Recursive dependency-tree scanning | ⚪ | CI tooling. |
| 2.7 | Pre-mutation receipt before any write | ⚪ | **Why grey:** TBP never installs anything. A skill "appears" only when an operator edits `TBP_SKILL_REGISTRY_FILE` out-of-band and restarts `brokerd` — there is no install path in the code to put a receipt in front of, and adding one would create the very runtime-mutation path the registry is designed not to have. The receipt for *actions* exists (`writeLeaf` before token emission, §4.1). **To close:** treat the registry file like a policy change: keep it in version control with signed commits, require a reviewed change record (who approved which skill, which `risk_tier`, which `scope`) before deploying it, and deploy it by the same signed pipeline as the other cell files. The change record is the pre-mutation receipt. |

## AST03 — Over-Privileged Skills (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 3.1 / 3.2 | Explicit, bounded permission manifest; minimize to real needs | ✅ | `SkillRecord.Scope` — exact literal comparison, never a prefix; an unregistered action carries zero privilege. |
| 3.3 | `shell:false` or command allowlist | ✅ | `tbp.pack.agent_hardening` (`policies/rego/pack_agent_hardening.rego`), violations `command-not-allowlisted`, `command-args-not-allowlisted` and `shell-metacharacter`: the resource of a command action is the command line — the **whole line must be allowlisted** (`allowed_command_lines`, exact after whitespace normalisation — **case included**, since an option changes meaning with case (`-r` / `-R`); `allowed_commands` allows a *bare* command only, so `git` listed does not allow `git -c core.sshCommand=…`, #267; `ls` does not allow `/tmp/ls`) and it may carry no shell metacharacter. Every action NOT known as non-executing (`read`, `write`, `http.send`… plus `extra_non_command_actions`) is judged as a command, so renaming `exec` to `invoke` or `tool_use` buys nothing (#268). Default-deny: with no allowlist nothing runs. `shell:false` itself is the *executor's* setting, since TBP never executes (see #180). Tested in `policies/tests/pack_agent_hardening_test.rego` (mutation-checked) and run in CI (`opa test`). |
| 3.4 | Explicit file paths, never broad globs | ✅ | `tbp.pack.agent_hardening` (`policies/rego/pack_agent_hardening.rego`), violation `glob-in-resource`: a `*` in a resource is refused. Confining paths to a set of roots is not shipped — TBP cannot tell a path from an identifier — and is written as a deployment-specific Rego prefix rule when needed. Tested in `policies/tests/pack_agent_hardening_test.rego` (mutation-checked) and run in CI (`opa test`). |
| 3.5 | Isolate credentials per skill, scheduled rotation | ⚪ | **Why grey:** TBP holds no skill credential. It authorizes an action (allow = authorizes) and never executes it (§4.5); the credential the executor uses to carry out the action lives in the executor's environment. `Scope` bounds which *resources* a skill may target, not which secrets it holds. What TBP does contribute: no agent can read the credential stores (`credential-store` violation, refused for every action and class) and every action is traced with its skill name. **To close:** give each skill's executor its own identity and secret (one service account or API key per skill, scoped to that skill's `scope` on the target side), keep them in a secret manager rather than on the agent's filesystem, and rotate them on the manager's schedule. Check in the target system's audit log that a skill's credential is only ever used for that skill's declared resources. |
| 3.6 | Flag `SOUL.md`/`MEMORY.md` writes for elevated review | ✅ | Same mechanism as 1.6: the write is refused below class W, and class W means plan approval + quorum, i.e. the elevated review. |
| 3.7 | Network permissions as a domain allowlist, default-deny egress | ✅ | `tbp.pack.agent_hardening` (`policies/rego/pack_agent_hardening.rego`), violations `egress-not-allowlisted`, `malformed-authority`, `opaque-uri`: a URL resource must target a host in bundle data `allowed_domains` (exact, or `*.example.org` for subdomains) **and a port**: an entry without a port opens only the scheme's default port (http 80, https 443…), another port is declared as `host:8443` (#270). Default-deny. Handles the `user@host` trick, trailing dots, case, `\\` and scheme-relative forms; a control character (`%00`, `%0a`, tab…) in the resource is refused (`control-character`, #269). **Two layers:** this is the policy layer; the network layer is the firewall (#186). Tested in `policies/tests/pack_agent_hardening_test.rego` (mutation-checked) and run in CI (`opa test`). |
| 3.8 | Block access to credential stores/`.env`/wallets/SSH/browser data | ✅ | `tbp.pack.agent_hardening` (`policies/rego/pack_agent_hardening.rego`), violation `credential-store`: refused for **every** action and class, reads included (`.env*`, `~/.ssh`, `.aws`, `.gnupg`, `.kube`, private keys/certs, wallets, browser data, `/etc/shadow`). Only the names it knows: extend via `extra_credential_files`/`extra_credential_dirs`. Also confirmed end to end through the real OPA in `deploy/selftest`. Tested in `policies/tests/pack_agent_hardening_test.rego` (mutation-checked) and run in CI (`opa test`). |

## AST04 — Insecure Metadata (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 4.1 | Description ↔ actual functionality match | ⚪ | Semantic analysis, not runtime. |
| 4.2 | ASCII-smuggling / zero-width / base64 scanning | ⚪ | Scanner concern — note the related but distinct fix in [OWASP LLM Top 10 LLM01.5](143-owasp-llm-top10.md) (Unicode instruction-smuggling on `Action`/`Resource`, already fixed). |
| 4.3 | Safe defaults, explicit opt-in for dangerous capabilities | ✅ | Applied: `risk_tier` is required, and a `high` or `critical` skill is invocable only under a plan (class I/W) or a plan plus quorum (class W) — see 4.5. No skill exists without an explicit registry entry, and devmode escape hatches need a flag plus an independent sentinel (#113). |
| 4.4 / 4.9 / 4.11 | Schema validation, strict JSON-key allowlist, pre-deserialization validation | ✅ | `loadSkillRegistry` (brokerd/main.go) rejects any empty action, empty provenance, or empty table — same fail-closed discipline as the rest of the repo. |
| 4.5 | Cross-reference declared `risk_tier` against permission scope | ✅ | `risk_tier` (`low`/`medium`/`high`/`critical`) is a required field of `SkillRecord`; `brokerd` refuses to start on a missing or unknown tier and on a scope wider than the tier allows (low ≤ 8 resources, medium ≤ 32, high ≤ 128, critical unbounded — a consistency guard, not a security boundary). Rule pack `tbp.pack.skill_tier` then gates invocation: `high` ⇒ class I/W (plan), `critical` ⇒ class W (plan + quorum). **Limit**: the tier is an operator declaration; a tier set too low is a provisioning fault only the out-of-band review of the registry file catches. |
| 4.6 | Block brand impersonation | ⚪ | Process/branding, not runtime. |
| 4.7 | Safe YAML parser (`safe_load`) | ⚪ N/A | TBP is Go, no PyYAML — but the principle is present: `dec.DisallowUnknownFields()` in `server.go:handleAction` rejects any JSON smuggling. |
| 4.8 | Parse in an isolated subprocess | ⚪ | OS-level. |
| 4.10 | Sandbox dependency installation | ⚪ | OS-level/CI. |
| 4.12 | Drop privileges before parsing | ⚪ | OS-level. |

## AST05 — Untrusted External Instructions (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 5.1 | Inventory of referenced external URLs/docs | ✅ | `TBP_SKILL_REGISTRY_FILE` is this out-of-band inventory. |
| 5.2 | Pin each reference to a content hash | ⚪ | **Why grey:** same as 5.3 — what a skill fetches is decided by the agent runtime. **To close:** as 5.3: vendor and hash-pin the documents in the build, and allowlist no hosting domain you have not reviewed. |
| 5.3 | Prefer signed inlining over runtime fetch | ⚪ | **Why grey:** what a skill loads at run time is decided by the agent runtime, not by the broker. TBP's part is the egress rule (5.4): a runtime fetch is refused unless its host is allowlisted, so the choice is enforced by *what you allowlist*. **To close:** vendor each skill and its referenced documents into the build, pin them by hash (2.2, 5.2), and do **not** add skill-registry or document-hosting domains to `allowed_domains`. Where a runtime fetch is unavoidable, allowlist that one host explicitly and record the decision in the change record for the policy bundle. |
| 5.4 | Restrict runtime fetches to a domain allowlist | ✅ | Same mechanism as 3.7 (`egress-not-allowlisted`): a runtime fetch whose resource is a canonical URL must target an allowed host. |
| 5.5 | Transitive review of the reference graph | ⚪ | Static analysis. |
| 5.6 | Fleet-wide visibility (which skill fetched which source) | ✅ | Every decision leaves a `KindDecision` leaf (§4.1) carrying the hash of the action and resource — hash-only (§6.2), so an investigator confirms "did skill X fetch source Y" by hashing the candidates, not by reading the resource in clear. **Limit:** TBP sees the fetches that go through it; a fetch made by the executor outside TBP is not seen, which is why network isolation (#186) matters. |

## AST06 — Weak Isolation (HIGH)

| # | Control | Status | Detail |
|---|---|---|---|
| 6.1 | Isolated container/sandbox, never host-mode by default | ⚪ | TBP is not a container runtime — already explicit deployment-prerequisite territory (`deploy/router-debian.md`: network isolation, never execution isolation). |
| 6.2 | Limit filesystem access to declared paths | ✅ | At the policy layer, `SkillRecord.Scope` *is* the declared set: exact literal resources, never a prefix, and an empty scope allows nothing (3.1/3.2); `glob-in-resource` refuses broad globs (3.4). OS-level confinement of the executor's filesystem is a separate layer — see 6.1 and 6.4. |
| 6.3 | Controlled network access, authenticated localhost bind (never bare `0.0.0.0`) | ✅ | Exactly what #124 closed for brokerd's data plane: mandatory mTLS, never plaintext TCP. Protects the broker, not a skill executed by the agent. |
| 6.4 | seccomp/AppArmor | ⚪ | OS-level, outside Go/TBP. |
| 6.5 | Inter-skill isolation (namespacing) | ⚪ | **Why grey:** TBP never executes the action itself ("the action executed is the translated action", §4.5), so there is nothing to namespace broker-side; isolation between skills is a property of the executor. TBP already keeps skills apart as *authorizations*: each skill is its own action name with its own exact `scope` and `risk_tier`, so one skill's grant never extends to another. **To close:** run each skill's executor in its own process, container or user (own UID, own working directory, no shared writable volume), with its own credential (3.5), and deny cross-skill communication at the network layer. Verify the network side with the cell-isolation test script tracked in #186. |
| 6.6 | Rate-limit + authenticate WebSocket, even on localhost | ✅ | Unix-socket 0660 + `SO_PEERCRED` doctrine (`opa_transport.go`), now also mTLS (#124). |
| 6.7 | Restrict hot-reload in production | ✅ | Exactly #92.A5 (OPA bundle revision-check, refuse on mismatch) + devmode doctrine. |

## AST07 — Update Drift (MEDIUM)

| # | Control | Status | Detail |
|---|---|---|---|
| 7.1 | Pin to an immutable hash in the inventory | ⚪ | **Why grey:** the registry pins each skill by its exact action name and scope, and is itself changed only out-of-band; the hash of the skill's *content* is checked where the skill is installed (see 1.3). **To close:** record `publisher@sha256:<hash>` in `provenance` and re-check it in your pipeline at each version change. |
| 7.2 | Disable auto-update / explicit re-approval in prod | ✅ | Exactly #92.A5 for the OPA bundle. |
| 7.3 | Cryptographic signature on every update | ✅ | Already done for the OPA bundle (§106, RSA signature verified by OPA itself). |
| 7.4 | Automatic re-scan on every version change | ⚪ | CI tooling. |
| 7.5 | Disable hot-reload outside dev | ✅ | Devmode doctrine (#113) + revision-check. |
| 7.6 | Subscribe to security advisories / CVE alerts | ⚪ | Organizational process. |

## AST08 — Poor Scanning (MEDIUM)

Almost entirely ⚪ out of TBP's scope — behavioral/semantic analysis, secret detection, multi-tool scan pipelines are CI/scanner territory; TBP must never claim to be a scanner. **Why grey:** a scan result is produced by a scanner, and TBP has no skill content to scan. **To close:** run your scanner in CI, add a skill to the registry only when it passed, and keep the scan date and result in the change record (see 9.1) — a stale scan is then a review item on that record, not a runtime check TBP could perform.

## AST09 — No Governance (MEDIUM)

| # | Control | Status | Detail |
|---|---|---|---|
| 9.1 | Centralized inventory (name, version, hash, date, installer, scan status) | ✅ · ⚪ (extra fields) | `TBP_SKILL_REGISTRY_FILE` is the inventory: action name, provenance, exact scope, `risk_tier`. Version, hash, date, installer and scan status are not fields of the record. **To close:** keep them in the change record next to the file (2.7) — one line per entry, reviewed with the file. |
| 9.2 | Assign `risk_tier` consistent with scope | ✅ | Same mechanism as 4.5: required tier, cross-checked with the scope size at load, exposed to OPA as `input.skill` and enforced by `tbp.pack.skill_tier`. Reviewing the tier remains an organizational step (9.5). |
| 9.3 | Approval registry (workflow, approver, date) | ⚪ | **Why grey:** the approval to admit a skill is an act of the operator's change process; TBP has no install path to gate (see 2.7). `ContractStore` seals *plans* with signed operator approval; skill admission is the registry-file change. **To close:** require two-person review and a signed commit on the registry file, and keep the approver and date in the change record. |
| 9.4 | Log invocations with sufficient audit detail | ✅ | Every decision already leaves a `KindDecision` leaf (§4.1), hash-only. |
| 9.5 | Review cadence based on risk_tier | ⚪ | Organizational process. |
| 9.6 | Formal revocation process | ✅ | Revoking a skill = removing its entry from the registry file and restarting `brokerd` (no hot-reload path exists, by design): from then on its actions are refused as `skill-unknown`. Cell quarantine (§7.3) and plan revocation in `ContractStore` cover the running-cell and plan cases. **To close (process):** write the revocation trigger and owner in your change process. |
| 9.7 | Agent identities as NHI, IAM, scheduled rotation | ✅ identity · ⚪ agent credentials | `AgentRegistry` (#125) closes agent *identity* (class and quota resolved by the broker, never self-declared; `transport_identity` binds an agent to its mTLS certificate, #124). **Why the rest is grey:** the agent's own credential — the client certificate it presents — comes from the deployer's PKI, not from TBP. **To close:** issue short-lived agent client certificates from your CA, rotate them on a schedule shorter than the risk you accept, and update the agent's `transport_identity` only through the out-of-band registry file. For rotating *TBP's own* keys, see the next row. |
| 9.7 (TBP's own keys) | Scheduled rotation of the keys TBP holds | ✅ procedure | The mechanism is already in the code: token signature keys are matched by `kid` (SHA-256 of the public key) in a pinned **keyring** that can hold several keys (`TBP_KEYRING_FILE`), and tokens live 30–60 s, so an overlap window is short. Procedure for the token-issuing key: (1) create the new key (HSM or seed) and note its `kid`; (2) add its public key to `TBP_KEYRING_FILE` next to the old one, sign a `provisioning-transition-pepd` proof (the keyring is a measured trust file since #192: an edit without a proof refuses to start) and restart `pepd` — it starts closed until the quorum reconfirms (#93); (3) point `brokerd` at the new key and restart it; (4) after at least one token lifetime (60 s), remove the old `kid` from the keyring, with a new proof, and restart `pepd` again. Operator and quorum keys (`TBP_OPERATOR_KEYS_FILE`, `TBP_QUORUM_KEYRING_FILE`, the genesis manifest) are measured the same way, and a change of *controllers* is signed by the controllers as previously attested (#218): `deploy/recovery.md` gives the procedure for a lost key (replace in place, k of the remaining controllers sign), a lost quorum (re-engagement) and a stolen key, and `pepd`/`brokerd` warn at start when k = 1 or when there is no spare key (n ≤ k). **Limit:** controller rotation and loss recovery are exercised by Go tests on the real start-up code (named in `deploy/recovery.md`) but not by `deploy/selftest`; the token-key rotation above is derived from the code and not exercised. |

## AST10 — Cross-Platform Reuse (MEDIUM)

Almost entirely ⚪: TBP is a closed, single-architecture system by construction ("no direct client → server path") — the very notion of "same skill across multiple platforms" doesn't apply. **Why grey:** a *Universal Skill Format* is an interchange format between skill marketplaces; TBP's registry is a local, out-of-band table (`TBP_SKILL_REGISTRY_FILE`) that never imports a manifest. **To close (if you consume marketplace skills):** translate each accepted skill into a registry entry by hand or in your own pipeline (`provenance`, `scope`, `risk_tier`) and keep the original manifest with the change record.

---

## Summary

**Closed by SkillRegistry (#165, PR #166)**: publisher identity/provenance (1.1), version pinning pattern (2.2), permission scope (3.1/3.2), manifest schema validation (4.4/4.9/4.11), skill inventory (5.1), third-party supplier relationship gaps confirmed independently by [#144](144-csa-maestro.md), [#145](145-mitre-atlas.md), [#148](148-iso-iec-42001.md), [#152](152-iso-iec-27001-27002.md), [#153](153-nist-csf-800-53.md).

**Closed by the agent-hardening rule pack** (`tbp.pack.agent_hardening` (`policies/rego/pack_agent_hardening.rego`)): 1.6/3.6 (agent identity/memory files need class W), 3.3 (command allowlist, no shell metacharacters), 3.4 (no broad globs), 3.7/5.4 (egress domain allowlist, default-deny), 3.8 (credential stores refused for every action). Configuration is bundle data, documented in [`policies/README.md`](../policies/README.md).

**Closed by the skill-tier rule pack** (`tbp.pack.skill_tier`, `policies/rego/pack_skill_tier.rego`): 4.5 and 9.2 — required `risk_tier` in the registry, consistency with scope checked at startup, gating by agent class in Rego.

**Grey rows with a deployer action** (why grey and how to close are in each row): pre-mutation receipt for skill installation (2.7), per-skill credentials (3.5), signed inlining vs runtime fetch (5.3), inter-skill isolation (6.5), agent client-certificate rotation (9.7). None of them needs new TBP code; each is closed by a deployment or change-management practice.

**Design note — can a SkillRegistry entry be modified?** No runtime mutation path exists for either an agent or a hot-reload; only an operator editing the out-of-band file and restarting `brokerd` can change a skill record. See [#165](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165) for the full design rationale.

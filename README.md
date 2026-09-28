# TBP-NETWORK

Network-level implementation of the **[Teleological Bounding Protocol (TBP)](https://github.com/philippeabraxas-jpg/Responsible-Alliance-Protocol)** —
attested governance of AI agent actions over a network, from a single
machine to enterprise deployments up to WWW scale.

> *« Existing access control decides whether you get in; TBP decides what
> you're allowed to do once inside — and proves it. We govern capabilities,
> not models. »*

**Never a partnership by trust — only by an attested handshake.** That's
what this repository is: the inter-entity handshake (spec §3) and
everything around it — NAC, PEPs, cell registries — that extends TBP's
governance from a single machine to a network of entities that have to
trust each other without simply trusting each other.

## What TBP is — and isn't

**TBP does not close every hole; it audits every hole.** That's not a
limitation to work around, it's the founding postulate (spec §1: *"we do
not close every hole; we rank holes by impact and mitigate proportionally
— governance is allocation, not completeness"*). TBP is not a
self-sufficient security system — it doesn't replace SELinux, firewalls,
IAM, or OS-level sandboxing, and it never will by design. What it does is
narrower and non-negotiable: no governed action executes without a
cryptographically provable decision, and no decision — allow or deny —
escapes the audit chain unprovable and uncorrupted. TBP is a governance
and attestation layer over whatever enforcement stack a deployment already
has, not a substitute for it.

**How much TBP restricts is a deployment choice, not a protocol
property.** Between allow-all (monitor mode, everything logged, nothing
blocked) and deny-all sits a whole spectrum, shaped by which OPA rule
packs a cell loads, which scale (below) it operates at, and how far it
pushes plan contracts, quorum, and the (planned) risk-scoring layer
([#177](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/177)–[#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181)).
A personal lab and a regulated production cell can run the identical
protocol at very different points on that spectrum, and that's by design,
not a gap — see "Next planned work" below for the rule-pack / posture
presets planned for the per-scale admin console.

**Exactly two things don't move, at any point on that spectrum**:

1. **The three non-derogable invariants** carried by the core protocol —
   **F-STABILITY** (no autonomous value transfer / market manipulation),
   **I-INTEGRITY** (no autonomous agent control of industrial/OT systems),
   **W-MONOPOLY** (no integration into lethal kill chains or WMD
   development) — see
   [`tbp4.2.1/README.md`](tbp4.2.1/README.md#the-solution-fiw-invariants).
   These are the categories where a bad action isn't reversible by
   revoking access after the fact; no deployment posture, rule pack, or
   scale ever relaxes them.
2. **Provable audit** — that an action happened, and that the record of it
   hasn't been tampered with, is always provable by construction (hash-only
   leaves, Merkle-anchored chain, §6.2), independent of how permissive or
   strict the policy loaded on top of it is.

Everything else — how wide the allowed envelope is, how much friction an
operator accepts, which compositions require a human signature — is a
choice between complexity, operational need, and what a given deployment
can actually run, not a property of the protocol itself.

**Note on language**: the reference specification is now
**[`docs/spec-en-v1.0.md`](docs/spec-en-v1.0.md)** (English) — this is the
document code and audits should be built against. The author's working
note — denser, less linear, useful for design-rationale digging, but not
the one to cite — exists in two languages:
[`docs/spec-v1.4.10.md`](docs/spec-v1.4.10.md) (English) and
[`docs/spec-v1.4.10.fr.md`](docs/spec-v1.4.10.fr.md) (original French).
The same convention applies across the repo: every document originally
written in French now has an English primary at its original path, with
the French original kept beside it as `<name>.fr.md`. The glossary
(`docs/glossaire.md`) is still French-sourced (§14 of the French doc is
its terminology source of truth) with an English gloss column for
readability — this is unchanged.

## Start here

The full specification is **[`docs/spec-en-v1.0.md`](docs/spec-en-v1.0.md)**
— it is the source of truth for any design or configuration decision in
this repo. This README only summarizes what's needed to get oriented;
when in doubt, the spec governs. The working note
(`docs/spec-v1.4.10.md`, English translation of the French original) is
not superseded content-wise — it's the same protocol, developed there
first — but it is not the citable reference going forward.

Useful landmarks for reading it:
- **§1 Doctrine** — the ten non-negotiable rules.
- **§13 Implementation sequence** — the order to follow (HSM → OPA → PEP →
  NAC → translator), and the exact scope of pilot P1.
- **§9.1 Friction budget** — the latency and arbitration-rate thresholds
  that determine whether a TBP deployment is actually working; keep these
  in view for every configuration decision.
- **[`docs/glossaire.md`](docs/glossaire.md)** — one canonical term per
  concept, to be used consistently across the code and docs of this repo
  (see `CONTRIBUTING.md`).

## Relation to the main TBP repository

The protocol itself — specification, formal doctrine, adversarial audits,
core implementation (HSM signing, Merkle audit chain, OPA policy engine) —
lives in [Responsible-Alliance-Protocol](https://github.com/philippeabraxas-jpg/Responsible-Alliance-Protocol),
licensed Apache 2.0 (open), and is vendored in-tree here at `tbp4.2.1/`
as a git submodule pinned to a specific commit — a pointer, not a fork:
this repository is never the place to file an issue or PR against that
code, only against the network-rollout pieces below. **This repository
is the network-scale rollout** of that same protocol: NAC, local PEPs,
cell registries, the inter-entity handshake — the pieces needed to take
TBP from a single governed machine to a governed network. As of this
notice, this repository's own code is Apache 2.0 too (see Licensing
below) — the same license as the core protocol, one license across both
repositories, not two. It previously used a closed license during an
initial pilot phase; that phase is over.

**Keeping the submodule current**: `tbp4.2.1/` does not update itself —
bumping it to a newer commit of `Responsible-Alliance-Protocol` is a
deliberate, reviewed action (`cd tbp4.2.1 && git checkout <commit> && cd
.. && git add tbp4.2.1 && git commit`), never automatic. A pinned
submodule that silently falls behind a security fix upstream is worse
than no submodule at all — treat bumping it with the same care as any
other dependency update, and check the core repo's own changelog first.

## Compliance mapping

TBP has been checked control-by-control against 21 external security,
AI-governance, and regulatory frameworks — not as a marketing claim, but as a
gap analysis honest about what's covered, what's partial, and what's
structurally outside TBP's scope. The full breakdown (one file per standard,
with citations to the exact mechanism behind every ✅) lives in
[`tbp-compliance/`](tbp-compliance/README.md); this table is the summary.

| Standard | Status | Detail |
|---|---|---|
| OWASP Agentic Skills Top 10 (AST10) | 🟡 Partial | [tbp-compliance/142-…](tbp-compliance/142-owasp-agentic-skills-top10.md) |
| OWASP GenAI LLM Top 10 (2026) | 🟡 Partial | [tbp-compliance/143-…](tbp-compliance/143-owasp-llm-top10.md) |
| CSA MAESTRO (7-layer threat model) | 🟡 Partial | [tbp-compliance/144-…](tbp-compliance/144-csa-maestro.md) |
| MITRE ATLAS (16 tactics) | 🟢 Full | [tbp-compliance/145-…](tbp-compliance/145-mitre-atlas.md) |
| EU AI Act | 🟡 Partial | [tbp-compliance/146-…](tbp-compliance/146-eu-ai-act.md) |
| NIST AI RMF 1.0 | 🟡 Partial | [tbp-compliance/147-…](tbp-compliance/147-nist-ai-rmf.md) |
| ISO/IEC 42001:2023 (AIMS) | 🟢 Full | [tbp-compliance/148-…](tbp-compliance/148-iso-iec-42001.md) |
| ISO/IEC 22989:2022 (terminology) | ⚪ N/A | [tbp-compliance/149-…](tbp-compliance/149-iso-iec-22989.md) |
| ISO/IEC 23894:2023 (AI risk mgmt) | 🟡 Partial | [tbp-compliance/150-…](tbp-compliance/150-iso-iec-23894.md) |
| US federal AI directives (M-25-21/22) | 🟡 Partial | [tbp-compliance/151-…](tbp-compliance/151-us-federal-ai-directives.md) |
| ISO/IEC 27001/27002:2022 | 🟢 Full | [tbp-compliance/152-…](tbp-compliance/152-iso-iec-27001-27002.md) |
| NIST CSF 2.0 / SP 800-53 | 🟡 Partial | [tbp-compliance/153-…](tbp-compliance/153-nist-csf-800-53.md) |
| SOC 2 (5 Trust Services Criteria) | 🟡 Partial | [tbp-compliance/154-…](tbp-compliance/154-soc2.md) |
| GDPR | 🟡 Partial | [tbp-compliance/155-…](tbp-compliance/155-gdpr.md) |
| SLSA v1.0 (build provenance) | 🟢 Full | [tbp-compliance/156-…](tbp-compliance/156-slsa.md) |
| OWASP SCVS (component verification) | 🟢 Full | [tbp-compliance/157-…](tbp-compliance/157-owasp-scvs.md) |
| CIS Benchmarks | 🟢 Full | [tbp-compliance/158-…](tbp-compliance/158-cis-benchmarks.md) |
| NIST SP 800-207 (Zero Trust) | 🟡 Partial — strongest match | [tbp-compliance/159-…](tbp-compliance/159-nist-800-207-zero-trust.md) |
| IEC 62443 (OT/industrial) | 🟡 Partial | [tbp-compliance/160-…](tbp-compliance/160-iec-62443.md) |
| FIPS 140-3 (crypto module validation) | 🟢 Full — documentary scoping | [tbp-compliance/161-…](tbp-compliance/161-fips-140-3.md) |
| OWASP API Security Top 10 (2023) | 🟢 Full | [tbp-compliance/162-…](tbp-compliance/162-owasp-api-security-top10.md) |

**8 standards Full, 12 Partial, 1 Not applicable** (terminology-only, no
controls to rate). "Partial" is not a failing grade here — several frameworks
(EU AI Act, NIST AI RMF, SOC 2 Availability) are inherently partial because
part of what they ask for is an organizational process TBP cannot itself be;
each file states plainly which gaps are real code work versus a documented,
deliberate design tradeoff (fail-closed over availability) versus genuinely
out of scope. Two recurring findings drove real fixes: a `SkillRegistry`
gap independently confirmed by seven frameworks (#165/PR #166), and a
BOLA/Broken-Authentication gap on `POST /v1/actions` found by the OWASP API
Security Top 10 catalog (#163/PR #164) — see
[`tbp-compliance/README.md`](tbp-compliance/README.md) for the full list of
threads running across the series.

## Repository structure

```
tbp4.2.1/             Git submodule: the core protocol (Responsible-Alliance-Protocol,
                      pinned commit) — working implementation, tests, live at
                      invarian.fr; includes tbp-v4-hard-shield/ (the OPA policy
                      engine this repo's PEPs enforce against). Not copied: run
                      `git submodule update --init` to fetch it; source of truth
                      and issue tracker for this code stay in that repository.
docs/                 Specification (spec-en-v1.0.md, reference; spec-v1.4.10.md +
                      spec-v1.4.10.fr.md, working note EN/FR), glossary, audits
figs/                 Figures referenced by the spec (see MANIFEST.md)
policies/
├── README.md          How to generate capabilities.json correctly
├── gen_capabilities.sh + validate_determinism.go   Generation + determinism gate
└── rego/               Illustrative example Rego policies
config/
├── nftables/           Local PEP redirection + P1 router rules (§4.1, §5.1)
├── freeradius/          802.1X / EAP-TLS + enrolment/revocation scripts (§5.1)
└── sysctl/               Generic kernel hardening
src/
├── pep/                 Local policy enforcement point (§4.1, §4.1-bis, §4.3):
│                        CWT/COSE token validation (Ed25519), memory-bounded
│                        fail-closed anti-replay, clock-status degraded mode,
│                        execution quotas, plan-as-contract gate, monitor→closed
│                        modes, pepd daemon
│   └── postgres-extension/  Two-hook in-process PEP for PostgreSQL (§4.4)
├── broker/               Cell broker (§5.1): single entry point of the decision
│                        flow — orchestration, token issuer, emission envelope,
│                        HTTP server (brokerd), epoch/quorum/plan-contract wiring
├── cluster/              Multi-cell fencing (§7.2–§7.5): single-authority epochs
│                        (m-of-n verified, monotone, equivocation-detected),
│                        k-of-n quorum for class W, mirror/canary promotion
├── registry/             Cell registry (§6): Tessera POSIX cell log with signed
│                        checkpoints, disk backpressure, anchoring + TSA,
│                        attested state manifest, measured boot (§6.3)
├── supervision/          Independent monitor (§2, §6.2, §7.1): verified chain
│                        reading (ChainWatcher), divergence alerting, failover
│                        detection, read-only console, supervisord
├── telemetry/            Flow metadata exporters, anti-dribble (§4.1-bis)
└── translator/            Translator (§4.5): runtime hardening (hardened systemd
                           unit, seccomp allowlist, confinement audit) + controlled
                           degradation state machine (structured-only, no cloud
                           fallback; mirror failover / human escalation /
                           default-deny per system class) + quality measurement
                           (corpus replay, per-class FNR/FPR gate blocking CI,
                           stratified human sampling, `TBTM1` registry leaf)
deploy/                 Multi-machine deployment guides (router, cell, server,
                        supervisor) with per-machine checklists, monitor→closed
                        posture switch, and an executable selftest (82 controls)
scripts/genesis/        Genesis ceremony tooling (epoch 0, controller keys §12)
lab/                    docker-compose PoC + containerlab P1 topology + netns
                        tests (802.1X fail-closed, MAB/IoT VLAN, OCSP remediation)
tests/
├── p1_friction/         Friction budget (§9.1): thresholds + Go harness + leading indicators
└── p2_redteam/           Attack scenarios (§13) + evidence-producing runner
.github/                Issue templates, CI (Rego determinism gate + lint)
```

**Current status (as of 2026-09-22): the rollout code is implemented and
tested along the full path — genesis → fencing → registry → broker → PEP →
supervision → translator → deployment.** Every `src/` package carries its
own test suite (Go unit/integration tests, Python for the audit and
measurement tooling), and `deploy/selftest/` executes the deployment
guides end to end (**82 controls, 0 failures** — a guide that drifts from
the code breaks there, not at the operator's). No PR is open against this
repository right now — the backlog that was in flight (T25 controlled
degradation, T38 bounded-async registry durability, T26 translator
quality measurement) has all merged. Two items remain open and tracked
deliberately, neither blocking the pilot: the English translation of the
remaining French documentation ([#83](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/83),
in progress — most of `deploy/` and `docs/` already have English
primaries, see "Note on language" above), and the inter-domain layer
(spec §13 — deferred by the spec itself, tracked in
[#33](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/33) so
"deferred" stays visible instead of silently absent). What is
deliberately **not** here yet beyond that: the native per-language
translator corpora (to be constituted at the pilot, §15 — the pipeline
that replays and gates on them is built) and the human-arbitration
escalation path (brokerd v1 accepts only the `structured` translator).
Do not deploy `config/` as-is — every file there says so explicitly,
worth repeating here too. The protocol this rollout code governs against
is not a skeleton either: `tbp4.2.1/` vendors the working core (HSM
signer, Merkle audit chain, OPA policy engine, tests, adversarial review
process) in-tree via git submodule, pinned to a specific commit — present
here without being copied or duplicated.

## Configuration guidance — where to start

Based on the implementation sequence (§13) and the pilot P1 scope (§13,
§9.1: 1 server VLAN, Debian router, 2 cells, 802.1X, central registry,
measured user-experience regression = 0):

1. **Genesis and keys** (§7.2, §3.2) — before anything else: a genesis
   ceremony signed by the controller quorum (m-of-n, HSM), anchored
   out-of-band. [`scripts/genesis/`](scripts/genesis/) provides the
   epoch-0 tooling (dev path included); the ceremony itself remains
   procedural, not code — nothing in this repo replaces it.
2. **Cluster fencing** (§7, §13 step 2) — epoch issuance and rotation,
   controller quorum (k-of-n) for class-W actions, mirror/canary
   promotion. Required before any multi-cell deployment, including the
   2-cell P1 pilot below — a single cell can defer this, a pilot cannot.
   Implemented in [`src/cluster/`](src/cluster/) (single-authority epoch
   tracker, quorum, promotion by proof of receipt — no private key held
   there) and wired into the broker ([`src/broker/`](src/broker/)).
3. **OPA + registry** — install OPA, generate `policies/capabilities.json`
   following [`policies/README.md`](policies/README.md) (strip
   `http.send` and `time.now_ns` before any deployment, never after;
   `validate_determinism.go` and the determinism CI gate enforce this),
   start it with `lab/docker-compose.yml` to iterate on rules locally.
   The attested manifest and measured boot (§6.3, §13 step 3) — a cell's
   own state must be provable before its decisions are — are implemented
   in [`src/registry/`](src/registry/) alongside the cell log,
   backpressure and anchoring.
4. **PEP** — the first genuinely governed perimeter (§13), implemented in
   [`src/pep/`](src/pep/): token validation (CWT/COSE, Ed25519),
   memory-bounded fail-closed anti-replay, clock-status degraded mode,
   execution quotas, and the plan-as-contract gate (§4.2, §13 step 4 —
   token validation alone governs a single action, not the multi-step
   plan an operator actually signs). Read
   [`src/pep/README.md`](src/pep/README.md), and
   [`config/nftables/pep-redirect.nft`](config/nftables/pep-redirect.nft)
   for the Debian-side network redirection. **Deploy in monitor mode
   first** (log, no blocking) — never `closed` on first rollout (doctrine
   §5.3); the posture switch procedure is
   [`deploy/monitor-to-closed.md`](deploy/monitor-to-closed.md). For
   PostgreSQL, the in-process two-hook PEP lives in
   [`src/pep/postgres-extension/`](src/pep/postgres-extension/) (§4.4).
5. **NAC in parallel** — [`config/freeradius/`](config/freeradius/):
   802.1X/EAP-TLS reusing the same PKI as the handshake (§3), fail-closed
   enforced at the switch level (not just on the RADIUS side), no
   RADIUS-assigned VLAN in v1. The `lab/tests/` netns suites exercise the
   fail-closed, MAB/IoT-VLAN and OCSP-remediation paths.
6. **Host hardening** — [`config/sysctl/99-tbp-hardening.conf`](config/sysctl/99-tbp-hardening.conf)
   on every machine running a TBP component (broker, PEP, registry).
7. **Translator last** (§13) — once everything else is stable. Delivered
   in [`src/translator/`](src/translator/): runtime hardening (non-root,
   cap-drop, seccomp — distinct from `dm-verity`, which protects the
   image at rest, not the runtime), the controlled-degradation state
   machine (structured-only, no cloud fallback), and quality measurement
   (`measure.py` replays the corpus and gates CI on FNR/FPR regression,
   `tmetrics` inscribes the result as a registry leaf, T26, §4.5) — the
   corpora themselves are constituted at the pilot, not shipped here.
8. **Multi-machine deployment** — [`deploy/apercu.md`](deploy/apercu.md)
   is the entry point (what, where, why, prerequisites); it synthesizes
   the per-role guides (router, cell, server, supervisor) and their
   per-machine acceptance checklists. `deploy/selftest/` **executes**
   the guides (`bash deploy/selftest/selftest.sh`, 82 controls,
   fail-closed) — run it before touching a real machine.

At every step, measure against the friction budget (§9.1) — see
[`tests/p1_friction/`](tests/p1_friction/) for the exact thresholds and
the runnable harness. The pilot fails if latency or arbitration rate
exceed these thresholds, even if everything else works.

## Roadmap: right-sized deployment scales

TBP is a complex, full-scale governance system — cluster fencing, quorum,
an independent supervisor, a hardened translator, an inter-entity
handshake. Not every deployment needs all of it. A single-server small
business that wants "no AI agent acts without a provable, logged reason"
does not need two-cell failover any more than a home network needs a
SOC. The plan is to package what already exists in this repository into
**four deployment scales**, each a strict superset of the previous one —
same primitives throughout (fail-closed, hash-only leaves, monitor before
closed), more of them wired together as the scale goes up, and the
security posture — and the operational complexity that buys it —
increasing accordingly:

- **Scale 1 — Single machine.** One host, one governed perimeter: `pepd`
  in front of the service, a local OPA sidecar, a single `CellLog`
  registry. No cluster fencing (nothing to fence with one cell), no NAC
  (nothing to admit onto a network — it's one box), no broker or
  supervisor daemon. Genesis collapses to a single operator keypair,
  documented as such rather than pretending a quorum ceremony that isn't
  one. Lowest operational complexity: get the OPA rules right, deploy in
  monitor mode, watch the friction budget, earn `closed`.
- **Scale 2 — Small team / single site.** A handful of machines on one
  LAN behind one `brokerd`, still a single registry (no fencing yet —
  one authoritative cell is still enough at this size), NAC added
  (`config/freeradius/`, 802.1X at the switch) to admit machines onto the
  segment, host hardening applied everywhere. One more daemon, one more
  subsystem, same registry model as scale 1.
- **Scale 3 — Resilient multi-cell.** What is already fully built and
  documented as the pilot P1 deployment above: 2+ cells, cluster fencing
  (epoch issuance/rotation, k-of-n quorum for class-W actions,
  mirror/canary promotion), an independent supervisor with a read-only
  console, the hardened translator with controlled degradation, the full
  `deploy/` guide sequence and its 82-control selftest. For organizations
  that can't tolerate a single cell going down, or whose governed agents
  justify the extra machines.
- **Scale full — Multi-entity.** The inter-entity handshake (§3):
  proving policy, history continuity, and liveness across organizational
  boundaries, not just across cells of the same organization —
  federation between independently-governed TBP deployments that have to
  trust each other without trusting each other. Deliberately not started
  yet; tracked in [#33](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/33)
  (T32) so it stays visible as a later, distinct phase rather than
  silently absent. This is genuinely new protocol work, not just more
  machines running what already exists.

**Honesty about where this stands**: scale 3 is delivered today under
the pilot-P1 name used throughout this README. Scales 1 and 2 are not
yet packaged as their own guides — they're reachable today by deploying
a subset of what's documented (skip cluster fencing and NAC for scale 1,
add NAC but keep one cell for scale 2), but that path isn't written down
yet, and nothing currently stops someone from wiring it correctly on
their own subject to the same doctrine. Scale full requires actual new
code (§3's three proofs), not just new guides.

### Next planned work

Two work streams, tracked as separate issues because they're different
kinds of effort:

1. **Per-scale deployment guides, plus admin tooling sized to each
   scale** ([#86](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/86)).
   Turning the scales above into `deploy/scale-1.md` /
   `deploy/scale-2.md` — scale 3 already has its guide sequence, it's
   `deploy/apercu.md` and the per-role guides it synthesizes — is half
   of this: a documented, selftest-covered path per scale rather than
   "the pilot guide, minus what you figure out to skip". The other half
   is operator-facing tooling, which today is a
   read-only JSON API (`src/supervision/console.go`: `/v1/arbitration`,
   `/v1/epoch`, `/v1/indicators`) plus raw files and CLIs (Rego policies
   edited by hand, `policies/gen_capabilities.sh` /
   `validate_determinism.go` to validate and strip before deploy; the
   registry read by `ChainWatcher`'s verified scan, exercised in tests
   and selftest but with no browsing UI). Three dedicated tools are
   planned on top of what already exists, each scoped to what a given
   scale actually needs (a scale-1 operator doesn't need multi-cell
   arbitration views; a scale-3 one does):
   - a **supervision dashboard** on top of the existing read-only
     console — human-facing, still read-only by construction (§7.1 "the
     supervisor sees everything, touches nothing" carries over
     unchanged, D81);
   - a **rule/policy editor** for the OPA Rego bundle — edit, test
     against the same determinism and capability-stripping gates
     `validate_determinism.go` already enforces, and diff against what's
     deployed, before anything reaches production; the per-scale version
     of this is a library of **rule packs** and named posture presets
     (permissive ↔ closed) an operator selects rather than hand-writes,
     so tuning where a cell sits on the allow-all/deny-all spectrum ("What
     TBP is — and isn't" above) doesn't require Rego fluency at scale 1
     the same way it does at scale 3;
   - an **audit browser** for the registry — search and filter the leaf
     history (`KindDecision`, `KindTelemetry`, `KindQuorum`, …) with the
     same third-party-verifiable checkpoint proof `ChainWatcher` already
     does programmatically, made legible to a human auditor instead of a
     test assertion.
2. **Standards alignment — from a proprietary policy model to an
   interoperable one** ([#87](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/87)).
   TBP's rule taxonomy (classes F/I/W/OUT, §5.3),
   its audit trail (hash-only Merkle-logged leaves, §6.2), and its
   control set (fail-closed, monitor-before-closed, quorum for
   high-stakes actions) are TBP-specific today — internally consistent
   and tested, but not mapped to any external framework an auditor or a
   regulator would already recognize. The work is to identify which
   existing (and emerging) standards this maps to, and where the gaps
   are — not to assume any of these apply, or that TBP already satisfies
   them, without doing that mapping first. Candidates worth evaluating
   as a starting point: **ISO/IEC 42001** (AI management system
   standard — the closest fit for an "AI governance" claim), the **NIST
   AI Risk Management Framework**, the **EU AI Act**'s logging and
   human-oversight obligations for high-risk systems (§4.1's leaf-per-
   decision and §4.2's plan-as-contract arbitration are structurally
   close to what Article 12/14 ask for — unverified, needs a real
   mapping, not an assumption), **NIST SP 800-207** (Zero Trust
   Architecture — the spec already positions TBP against Zero Trust in
   §3.3, a formal control-by-control comparison is the natural next
   step), and **OSCAL** (NIST's machine-readable control/assessment
   format — a plausible export target so TBP's own audit trail can feed
   standard compliance tooling instead of requiring a bespoke reader).
   This is research and specification work before it's code: the
   product is a gap analysis and, where a real mapping exists, either
   adapter code or documented equivalence — not a rewrite of the rule
   engine.

## Licensing

Dual license, by subtree:
- **`docs/` and `figs/`**: [CC BY 4.0](docs/LICENSE) — free to share and
  adapt with attribution.
- **Everything else** (`config/`, `src/`, `policies/`, `lab/`, `tests/`,
  `deploy/`, `scripts/`, `.github/`): [Apache 2.0](LICENSE) — same license
  as the core protocol in
  [Responsible-Alliance-Protocol](https://github.com/philippeabraxas-jpg/Responsible-Alliance-Protocol).
  This code was closed-license during an initial pilot phase; that
  phase is over — the project isn't viable built alone, and a
  governance protocol whose own doctrine is "never by trust, always by
  verifiable proof" shouldn't ask for trust on its own implementation.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute — code
included now, not just documentation — and the rules to follow when
editing the spec (terminology normalization, verified citations,
changelog).

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

**Note on language**: the reference specification is now
**[`docs/spec-en-v1.0.md`](docs/spec-en-v1.0.md)** (English) — this is the
document code and audits should be built against. The original French
document (`docs/spec-v1.4.10.md`) remains in the repo as the author's
working note: denser, less linear, useful for design-rationale digging,
but not the one to cite. The glossary (`docs/glossaire.md`) is still
French-sourced (§14 of the French doc is its terminology source of
truth) with an English gloss column for readability — this is unchanged
for now.

## Start here

The full specification is **[`docs/spec-en-v1.0.md`](docs/spec-en-v1.0.md)**
— it is the source of truth for any design or configuration decision in
this repo. This README only summarizes what's needed to get oriented;
when in doubt, the spec governs. The French working note
(`docs/spec-v1.4.10.md`) is not superseded content-wise — it's the same
protocol, developed there first — but it is not the citable reference
going forward.

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

## Repository structure

```
tbp4.2.1/             Git submodule: the core protocol (Responsible-Alliance-Protocol,
                      pinned commit) — working implementation, tests, live at
                      invarian.fr; includes tbp-v4-hard-shield/ (the OPA policy
                      engine this repo's PEPs enforce against). Not copied: run
                      `git submodule update --init` to fetch it; source of truth
                      and issue tracker for this code stay in that repository.
docs/                 Specification (spec-en-v1.0.md, reference; spec-v1.4.10.md, French working note), glossary, audits
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
                           default-deny per system class)
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
supervision → deployment.** Every `src/` package carries its own test
suite (Go unit/integration tests, Python for the audit and measurement
tooling), and `deploy/selftest/` executes the deployment guides end to
end (**82 controls, 0 failures** — a guide that drifts from the code
breaks there, not at the operator's). Bounded-async registry durability
(T38, §9.1) merged most recently
([#78](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/78)), just
after the translator's controlled degradation (T25, §4.5,
[#79](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/79)). One
backlog item is **in review** as an open PR:
[#80](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/80)
(translator quality measurement — corpus replay, per-class metrics,
registry leaf, T26, §4.5). What is deliberately **not** here yet: the
native per-language translator corpora (to be constituted at the pilot,
§15), the human-arbitration escalation path (brokerd v1 accepts only the
`structured` translator), and the inter-domain layer (spec §13 — deferred
by the spec itself, documented in issue #33). Do not deploy `config/`
as-is — every file there says so explicitly, worth repeating here too.
The protocol this rollout code governs against is not a skeleton either:
`tbp4.2.1/` vendors the working core (HSM signer, Merkle audit chain,
OPA policy engine, tests, adversarial review process) in-tree via git
submodule, pinned to a specific commit — present here without being
copied or duplicated.

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
7. **Translator last** (§13) — once everything else is stable. The
   runtime hardening and the controlled-degradation state machine are
   delivered in [`src/translator/`](src/translator/) (non-root, cap-drop,
   seccomp — distinct from `dm-verity`, which protects the image at rest,
   not the runtime; degradation: structured-only, no cloud fallback);
   quality measurement is in review
   (PR [#80](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/80)).
8. **Multi-machine deployment** — [`deploy/`](deploy/) holds the per-role
   guides (router, cell, server, supervisor), per-machine acceptance
   checklists, and `deploy/selftest/` which **executes** the guides
   (`bash deploy/selftest/selftest.sh`, 82 controls, fail-closed). Run
   the selftest before touching a real machine.

At every step, measure against the friction budget (§9.1) — see
[`tests/p1_friction/`](tests/p1_friction/) for the exact thresholds and
the runnable harness. The pilot fails if latency or arbitration rate
exceed these thresholds, even if everything else works.

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

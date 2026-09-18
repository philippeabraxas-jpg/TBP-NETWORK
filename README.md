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
figs/                  Figures referenced by the spec (see MANIFEST.md)
policies/
├── README.md          How to generate capabilities.json correctly
└── rego/               Illustrative example Rego policies
config/
├── nftables/           Local PEP redirection (§4.1)
├── freeradius/          802.1X / EAP-TLS (§5.1)
└── sysctl/               Generic kernel hardening
src/
├── pep/                 Local policy enforcement point (§4.1, §4.1-bis, §4.3)
│   └── postgres-extension/  Two-hook in-process PEP for PostgreSQL (§4.4)
├── telemetry/            Flow metadata, anti-dribble (§4.1-bis)
├── translator/            Translator runtime hardening (§4.5)
└── registry/              Cell registry / Tessera POSIX driver, disk backpressure (§6)
lab/                    docker-compose PoC + containerlab topology (TBD)
tests/
├── p1_friction/         Latency thresholds to respect (§9.1)
└── p2_redteam/           Attack scenarios to cover (§13)
.github/                Issue templates, CI (Rego + nftables lint)
```

**Current status: this repository's own rollout code is essentially a
skeleton.** The spec is corrected and complete; `config/` and `policies/`
contain concrete starting points; `src/`, `lab/` and `tests/` are, for
now, READMEs describing the expected scope (see §13 for the order to
fill them in). Do not deploy `config/` as-is — every file there says so
explicitly, worth repeating here too. The protocol this rollout code
governs against is not a skeleton: `tbp4.2.1/` vendors the working core
(HSM signer, Merkle audit chain, OPA policy engine, tests, adversarial
review process) in-tree via git submodule, pinned to a specific commit —
present here without being copied or duplicated.

## Configuration guidance — where to start

Based on the implementation sequence (§13) and the pilot P1 scope (§13,
§9.1: 1 server VLAN, Debian router, 2 cells, 802.1X, central registry,
measured user-experience regression = 0):

1. **Genesis and keys** (§7.2, §3.2) — before anything else: a genesis
   ceremony signed by the controller quorum (m-of-n, HSM), anchored
   out-of-band. Nothing in this repo replaces this step; it's procedural,
   not code.
2. **Cluster fencing** (§7, §13 step 2) — epoch issuance and rotation,
   controller quorum (k-of-n) for class-W actions, mirror/canary
   promotion. Required before any multi-cell deployment, including the
   2-cell P1 pilot below — a single cell can defer this, a pilot cannot.
   **No `src/` scope exists yet for this** (unlike `pep/`, `registry/`,
   `telemetry/`, `translator/` — see the skeleton note above): work
   directly from spec §7 until a `src/cluster/README.md` is written.
3. **OPA + registry** — install OPA, generate `policies/capabilities.json`
   following [`policies/README.md`](policies/README.md) (strip
   `http.send` and `time.now_ns` before any deployment, never after),
   start it with `lab/docker-compose.yml` to iterate on rules locally.
   Includes the attested manifest and measured boot (§6.3, §13 step 3) —
   a cell's own state must be provable before its decisions are; not yet
   covered by [`src/registry/README.md`](src/registry/README.md), which
   scopes the log/backpressure/anchoring side only.
4. **PEP** — the first genuinely governed perimeter (§13). Read
   [`src/pep/README.md`](src/pep/README.md) for the decisions to make
   before writing any code, and [`config/nftables/pep-redirect.nft`](config/nftables/pep-redirect.nft)
   for the Debian-side network redirection. **Deploy in monitor mode
   first** (log, no blocking) — never `closed` on first rollout (doctrine
   §5.3). Includes plan-as-contract arbitration (§4.2, §13 step 4) —
   token validation alone governs a single action, not the multi-step
   plan an operator actually signs; also not yet covered by
   `src/pep/README.md`.
5. **NAC in parallel** — [`config/freeradius/README.md`](config/freeradius/README.md):
   802.1X/EAP-TLS reusing the same PKI as the handshake (§3), fail-closed
   enforced at the switch level (not just on the RADIUS side), no
   RADIUS-assigned VLAN in v1.
6. **Host hardening** — [`config/sysctl/99-tbp-hardening.conf`](config/sysctl/99-tbp-hardening.conf)
   on every machine running a TBP component (broker, PEP, registry).
7. **Translator last** (§13) — once everything else is stable; see
   [`src/translator/README.md`](src/translator/README.md) for the
   expected runtime hardening (non-root, cap-drop, seccomp — distinct from
   `dm-verity`, which protects the image at rest, not the runtime).

At every step, measure against the friction budget (§9.1) — see
[`tests/p1_friction/README.md`](tests/p1_friction/README.md) for the exact
thresholds. The pilot fails if latency or arbitration rate exceed these
thresholds, even if everything else works.

## Licensing

Dual license, by subtree:
- **`docs/` and `figs/`**: [CC BY 4.0](docs/LICENSE) — free to share and
  adapt with attribution.
- **Everything else** (`config/`, `src/`, `policies/`, `lab/`, `tests/`,
  `.github/`): [Apache 2.0](LICENSE) — same license as the core protocol
  in [Responsible-Alliance-Protocol](https://github.com/philippeabraxas-jpg/Responsible-Alliance-Protocol).
  This code was closed-license during an initial pilot phase; that
  phase is over — the project isn't viable built alone, and a
  governance protocol whose own doctrine is "never by trust, always by
  verifiable proof" shouldn't ask for trust on its own implementation.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute — code
included now, not just documentation — and the rules to follow when
editing the spec (terminology normalization, verified citations,
changelog).

# Multi-machine deployment (T35, issue #61)

_Version française : [README.fr.md](README.fr.md)._

Deployment guides for the TBP network at scale: roles per machine,
installation order (§13), server-side instructions (§5.1). Target audience:
a **non-author** operator — every step carries a verifiable prerequisite,
an observable success criterion, and an "On failure: STOP". Never
continue after a red prerequisite.

**Start with the overview** — what, where, why, requirements:
[apercu.md](apercu.md). Come back here for the installation order, key
custody and the common steps.

## Roles and machines

| Role | Machine | Services | Guide |
|---|---|---|---|
| Router | dedicated Debian 12 (or VM, 2+ interfaces) | NAC 802.1X (FreeRADIUS EAP-TLS), nftables, VLANs §5.1 | [router-debian.md](router-debian.md) |
| Cell | one VM per cell (a, b, …) | broker, tessera registry, OPA, epoch tracker, HSM (genesis §12) | [cellule.md](cellule.md) |
| Server | application host (PostgreSQL, …) | PEP (pepd), acceptance via ITS OWN cell's broker only | [serveur.md](serveur.md) |
| Supervisor | independent VM | master registry (master chain), independent monitor, console | [superviseur.md](superviseur.md) |

Posture switch (monitor → closed, §5.3): [monitor-to-closed.md](monitor-to-closed.md).
Per-machine acceptance checklists: [checklists/](checklists/).

## Key custody (decision D97 — "no governance key outside its role")

| Key | Lives on | Never on | Reference |
|---|---|---|---|
| Quorum controller keys (genesis) | ceremony HSM (supervisor) | cells, servers, router | §12, scripts/genesis |
| Cell registry key (`cell_log.key`) | ITS cell only | any other machine | §4.1, pepd pattern |
| Leaf hashing salt (≥ 16 bytes) | the leaf producer | registries, supervisor | §6.2 |
| EAP-TLS private keys (PKI §3) | router (RADIUS) + supplicants | repo, cells | config/freeradius (to adapt) |
| Independent monitor key | supervisor | monitored cells | §2, §7.1 (T34) |

Repo consequence: `*.pem`, `*.key`, `config/freeradius/certs/` (to adapt, never copied),
`policies/capabilities.json` and selftest outputs are gitignored —
none of that is ever committed.

## Installation order (§13 instantiated — decision D98)

```
0. common prerequisites (below)
1. genesis             scripts/genesis — controller keys + epoch 0 (HSM)
2. fencing             epoch trackers on each cell (exercised by
                       deploy/selftest, 2-cell fencing phase)
3. OPA + registry      restricted capabilities, tessera registry
4. PEP / broker        pepd in MONITOR mode (§5.3), nothing else
5. router NAC          802.1X + VLANs — last network link
6. translator          optional, last (src/translator, T24)
```

The order is not cosmetic: governance (1-2) precedes policy
(3), which precedes application (4), which precedes network (5). Deploying
the NAC before fencing would admit clients without epoch
governance — exactly the defect fencing exists to prevent.

## Common steps

#### Step 1 — Verify the base binaries on EVERY machine

**Verifiable prerequisite**: shell access to the machine, sudo rights.

**Command**:

```bash
go version    # ≥ 1.24
opa version   # ≥ 1.0
python3 --version
```

**Observable success criterion**: all three commands answer with
conforming versions.

**On failure: STOP** — install the binaries before anything else; never
"adapt" a later step to work around a red prerequisite.

#### Step 2 — Fetch the repository and verify the deployment self-test

**Verifiable prerequisite**: step 1 green; the repository is cloned.

**Command**:

```bash
bash deploy/selftest/selftest.sh
```

**Observable success criterion**: `selftest.sh: tout est vert` — 82
controls (real single cell, 2-cell fencing, real
brokerd/supervisord daemons) and the formal guide verification
pass; report in `deploy/selftest/out/selftest-report.json`.

**On failure: STOP** — the guide you read has drifted from the code; read the
red control in the report, fix the cause (never the control).

#### Step 3 — Prepare genesis (supervisor machine, HSM required)

**Verifiable prerequisite**: step 2 green; HSM or SoftHSM (DEV
only — SoftHSM is never a governance root, §12);
`softhsm2-util` and `libsofthsm2.so` present.

**Command**:

```bash
N=3 M=2 AUTHORITY=cell-a GENESIS_HOME=scripts/genesis/out \
  bash scripts/genesis/genesis_dev.sh
```

**Observable success criterion**: `manifest.json`, `pubkeys/*.hex`,
`epoch0.json`, `anchor_epoch0.txt` produced under `GENESIS_HOME`.

**On failure: STOP** — no epoch 0 token, no cluster;
fix the ceremony, do not hand-craft an epoch 0.

#### Step 4 — Run the per-role guides in §13 order

**Verifiable prerequisite**: steps 1-3 green; genesis artefacts
distributed per the custody matrix above (pubkeys to cells,
never the controllers' private keys).

**Command**:

```bash
# In order: cells (deploy/cellule.md), servers
# (deploy/serveur.md), supervisor (deploy/superviseur.md),
# router (deploy/router-debian.md). Posture: MONITOR everywhere.
ls deploy/checklists/   # one acceptance checklist per machine
```

**Observable success criterion**: every acceptance checklist is green
on its machine; all PEPs answer `{"mode":"monitor"}` on
`GET /v1/mode`.

**On failure: STOP** — a red checklist blocks the rest; closed
mode is only requested after [monitor-to-closed.md](monitor-to-closed.md).

## Cross-cutting rules (repeated in every guide)

- **`config/` is a starting point to adapt**, never copied as-is
  (D99 — the formal checker breaks any reference without "adapt").
- **Monitor before closed** (§5.3): no closed-mode instruction as long
  as the §9.1 measurement points are not installed (D100).
- **§9.1 measurement points first**: the T27 harness
  (`tests/p1_friction/`) is the executable reference for the metrics.
- **Ed25519 everywhere** (§12); the leaf salt stays with the
  producer (§6.2); every decision leaves a leaf (§4.1).
- **Declared gaps**: `opa run --capabilities` disappeared in OPA ≥ 1.0:
  the supported form (bundle compiled with restricted capabilities) is
  documented in [cellule.md](cellule.md) and exercised by the selftest.
  The full netns/FreeRADIUS scenario runs in the lab
  (`lab/containerlab/`), not in the sandbox — the real causes are cited
  in [router-debian.md](router-debian.md). The `brokerd` and
  `supervisord` daemons (T37, issue #74) ship with their systemd units —
  the selftest's daemons phase exercises them for real.

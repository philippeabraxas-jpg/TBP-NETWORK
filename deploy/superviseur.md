# deploy/superviseur.md — "supervisor" machine (T35, issue #61)

_Version française : [superviseur.fr.md](superviseur.fr.md)._

The supervisor carries three functions INDEPENDENT from the cells (§2,
§7.1): the **master registry** (master chain, T6 — anchors of bundles per
epoch, healthy windows read by the §7.4 promotion), the **independent
monitor** (T34 — its own key and its own log, it NEVER writes
to the monitored chains) and the **console** (arbitrations, epochs,
§9.1 indicators). Genesis (scripts/genesis) is celebrated here, on HSM.

> The `supervisord` daemon (T37 — issue #74) assembles monitor and console;
> the daemons phase of `deploy/selftest/` executes step 3 of this guide
> against the real binaries (build, fail-closed witnesses, LIVE reads,
> honesty 503s when a source goes down). If a command below
> diverges from the selftest, the selftest breaks: fix the guide or the code.

#### Step 1 — Celebrate genesis (HSM)

**Verifiable prerequisite**: common steps of [README.md](README.md)
green; HSM plugged in (or SoftHSM — DEV only, never a governance
root §12); `softhsm2-util`, `libsofthsm2.so`, `go` present.

**Command**:

```bash
N=3 M=2 AUTHORITY=cell-a GENESIS_HOME=scripts/genesis/out \
  bash scripts/genesis/genesis_dev.sh
cat scripts/genesis/out/manifest.json   # controller keys, 2-of-3 quorum
```

**Observable success criterion**: `manifest.json`, `pubkeys/*.hex`,
`epoch0.json`, `anchor_epoch0.txt` produced; the manifest lists the agreed
M-of-N.

**On failure: STOP** — no genesis, no network. Never
hand-craft epoch0.json: the selftest's fencing phase shows
that an equivocated token is refused and alarmed — a hand-made epoch 0 would be
indistinguishable from a fault.

#### Step 2 — Distribute per custody (D97)

**Verifiable prerequisite**: step 1 green.

**Command**:

```bash
# To the cells: pubkeys/*.hex + epoch0.json (authenticated channel).
# To the servers: nothing from genesis (they have no governance to verify).
# HERE: the controllers' private keys stay in the HSM — never
# exported to another machine, never into the repo.
sha256sum scripts/genesis/out/pubkeys/*.hex
```

**Observable success criterion**: each cell acknowledges receipt of the
pubkeys and epoch0; no private key has left the HSM (HSM journal).

**On failure: STOP** — a controller private key copied out of the HSM
invalidates the ceremony: redo the genesis, revoke the old one.

#### Step 3 — Build and start supervisord (monitor + console, T37)

**Verifiable prerequisite**: step 1 green; the cells to monitor
are running (cellule.md step 7: each cell's brokerd serves its
supervision views on its Unix socket); `cell_log.vkey` of each
cell and of the master chain retrieved (PUBLIC checkpoint keys
— the only pieces needed for the verified scan, D97 custody); READ-ONLY
access to the monitored chains' directories granted to
the service user (dedicated group or ACL — `cell_log.key`
NEVER leaves the cell).

**Command**:

```bash
go build -o /usr/local/bin/supervisord ./src/supervision/cmd/supervisord
/usr/local/bin/supervisord 2>&1 | head -1   # without environment: must refuse

# /etc/tbp/cells.json — monitored chains (to adapt; public
# vkeys only):
#   {"cells":[{"cell_id":"cell-a","log_dir":"/var/lib/tbp/broker",
#              "origin":"cell-a",
#              "vkey_file":"/var/lib/tbp/broker/cell_log.vkey",
#              "manifest_dir":"/var/lib/tbp/broker/manifests"}],
#    "master":{"cell_id":"master","log_dir":"/var/lib/tbp/master",
#              "origin":"master",
#              "vkey_file":"/var/lib/tbp/master/cell_log.vkey"}}
# /etc/tbp/supervisord.env (0600) — example values, to adapt:
#   TBP_MONITOR_CELL_ID=monitor-01
#   TBP_SALT=<32-char hex — salt of the MONITOR's chain, generated here>
#   TBP_REGISTRY_DIR=/var/lib/tbp/supervision
#   TBP_CELLS_FILE=/etc/tbp/cells.json
#   TBP_CELL_BROKER_SOCKET=/run/tbp/broker-admin.sock  # ADMIN plane (§95):
#     supervisord reads GET /v1/supervision/* only, never POST /v1/actions —
#     the DATA-plane socket (broker.sock) doesn't serve these routes at all.
#   TBP_TICK_MS=5000
#   TBP_CONSOLE_SOCKET=/run/tbp/supervision.sock
install -m 0644 src/supervision/tbp-supervisord.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tbp-supervisord
curl -s --unix-socket /run/tbp/supervision.sock http://localhost/v1/epoch
```

**Observable success criterion**: the binary builds; launched without
environment, it exits immediately with
`supervisord: TBP_MONITOR_CELL_ID requis` (fail-closed — this refusal IS the
criterion); an unreachable cell brokerd AT STARTUP is fatal
too (source probe: no console whose sources are dead
at birth); the console answers in GET only: `/v1/epoch` returns
the cell's tracker state (LIVE read via brokerd, never a
cache), `/v1/arbitration` the queue of pending plans (sealed hash and
time bounds — never the steps), `/v1/indicators` the
§9.1 indicators and the health of the monitored chains. A brokerd that
GOES DOWN along the way ⇒ 503 `{"error":"source indisponible"}` on the
concerned route, never a frozen value or a zero-value (§1).

**On failure: STOP** — a supervisord that would start without salt,
without master chain or with an unreachable brokerd is fail-open:
fix the cause. A monitor that would write into the monitored
chains would violate §2/§7.1: the delivered unit makes it structurally
impossible (ProtectSystem=strict) — do not widen ReadWritePaths.

#### Step 4 — Monitor without writing

**Verifiable prerequisite**: step 3 green; `cell_log.vkey` of each
cell retrieved (PUBLIC checkpoint key — the only piece needed for the
verified scan, D97 custody).

**Command**:

```bash
# The monitor replays the cells' registries in verified READ mode.
# Any anomaly (epoch equivocation, anchor delay, continuation
# fraud) becomes an alert — never a corrective write.
go run ./deploy/selftest -phase fencing   # demonstrates the full loop
```

**Observable success criterion**: the fencing report shows the
`KindEpoch` leaves of BOTH cells read by verified scan (4 on cell-a, 3 on
cell-b in the reference scenario); alerts arrive at the Sink.

**On failure: STOP** — a scan that fails (invalid checkpoint,
broken chain) is an ALARM, not an incident to work around.

#### Step 5 — Healthy windows and promotion (§7.4)

**Verifiable prerequisite**: steps 1-4 green; the master chain anchors the
bundles per epoch.

**Command**:

```bash
# The healthy window is READ from the master, never measured by the canary:
# PromotionController refuses any promotion whose anchor or window
# is unavailable (partition = fail-closed refusal — demonstrated by the
# selftest's fencing phase: ErrPromotionAnchorUnavailable).
grep -n "HealthyWindow\|BundleAnchor" src/cluster/promotion.go | head -5
```

**Observable success criterion**: anchors and windows are published
per epoch in the master; the fencing selftest proves admission (healthy
window) and refusal (partition) with `KindPromotion` leaves on both sides.

**On failure: STOP** — without an epoch anchor, no promotion is
possible; that is the intended behavior, not an outage to repair.

## Hardening

systemd units on the T24 pattern (`src/translator/tbp-translator.service`);
the supervisor's unit is DELIVERED: `src/supervision/tbp-supervisord.service`
(T37 — structural read-only on the monitored chains, no
network family). The supervisor machine joins NO production VLAN
(§5.1) — its channel is supervision, not traffic.

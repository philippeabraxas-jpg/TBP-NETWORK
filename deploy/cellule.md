# deploy/cellule.md — "cell" machine (T35, issue #61)

_Version française : [cellule.fr.md](cellule.fr.md)._

A cell runs: the **broker** `brokerd` (T37 — issue #74), the
**tessera registry** (T7), **OPA** (T11, restricted capabilities
§12), the **epoch tracker** (§7.2) and the PEP `pepd`. Every decision
leaves a leaf (§4.1); the leaf salt stays on THIS machine
(§6.2). Posture at startup: **monitor**, always (§5.3).

> The mono phase of `deploy/selftest/` executes steps 1 to 6 of this
> guide against the real binaries, and the daemons phase executes step 7
> (real brokerd, real OPA, end-to-end action). If a command
> below diverges from the selftest, the selftest breaks: fix the guide
> or the code, never both behind each other's back.

#### Step 1 — Verify the machine prerequisites

**Verifiable prerequisite**: common steps of [README.md](README.md)
green; genesis artefacts received per the custody matrix
(`pubkeys/*.hex` of the controllers, `epoch0.json` — NEVER a controller
private key on this machine).

**Command**:

```bash
go version && opa version
ls "$GENESIS_HOME/manifest.json" "$GENESIS_HOME/pubkeys/" "$GENESIS_HOME/epoch0.json"
```

**Observable success criterion**: conforming versions; all three
genesis artefacts exist and are readable.

**On failure: STOP** — without genesis artefacts, no epoch
tracker; back to step 3 of the README.

#### Step 2 — Build the PEP (pepd)

**Verifiable prerequisite**: step 1 green; repository present on the machine.

**Command**:

```bash
go build -o /usr/local/bin/pepd ./src/pep/cmd/pepd
/usr/local/bin/pepd 2>&1 | head -1   # without TBP_SALT: must refuse
```

**Observable success criterion**: the binary builds; launched without
environment, it exits immediately with `pepd: TBP_SALT requis`
(fail-closed at startup — this refusal IS the criterion).

**On failure: STOP** — a PEP that starts without a salt is fail-open;
do not continue, fix the cause (binary, environment).

#### Step 3 — Generate the restricted OPA capabilities (§12)

**Verifiable prerequisite**: `opa` ≥ 1.0 installed (step 1).

**Command**:

```bash
bash policies/gen_capabilities.sh
# writes policies/capabilities.json (gitignored, never committed) and proves
# that a rule calling http.send is refused at load time
```

**Observable success criterion**: `vérification négative OK` displayed;
`capabilities.json` written; the forbidden built-ins (`http.send`,
`net.lookup_ip_addr`, `time.now_ns`, `opa.runtime`) are absent from it.

**On failure: STOP** — if a forbidden built-in is "absent from the
generated list", the OPA version has changed: review FORBIDDEN before any
deployment. Never hand-write capabilities.json.

#### Step 4 — Build the rule bundle WITH the capabilities (OPA ≥ 1.0)

**Verifiable prerequisite**: step 3 green; the pilot's own rules
written (the skeletons in `policies/rego/` are examples to adapt,
§14 — never a reference policy to copy).

**Command**:

```bash
# 'opa run' no longer has a --capabilities flag since OPA 1.0: the
# restriction is frozen at bundle compile time.
opa build --capabilities policies/capabilities.json policies/rego/ \
  -o /etc/tbp/bundle.tar.gz
sha256sum /etc/tbp/bundle.tar.gz   # this hash = TBP_POLICY_ID (claim −1)
```

**Observable success criterion**: the build succeeds; a rule calling
`http.send` added as a test breaks the build (remove the test
afterwards).

**On failure: STOP** — a bundle compiled without capabilities imposes
nothing at execution; do not work around it with `opa run` on bare .rego files.

#### Step 5 — Run OPA as a local server (bundle only)

**Verifiable prerequisite**: step 4 green; bundle present.

**Command**:

```bash
opa run --server --addr 127.0.0.1:8181 /etc/tbp/bundle.tar.gz &
curl -s http://127.0.0.1:8181/health
```

**Observable success criterion**: `/health` answers 200; OPA listens
ONLY on loopback (pepd alone calls it — no network exposure).

**On failure: STOP** — read the OPA log; an invalid bundle or an
already-taken port gets fixed before pepd, never after.

#### Step 6 — Start pepd in monitor mode (§5.3)

**Verifiable prerequisite**: steps 2 and 5 green; the cell's issuer
keyring installed (JSON `{"kid_hex": "pubkey_ed25519_hex"}`, 16-byte
kid); the quorum controllers' keyring installed likewise
(`TBP_QUORUM_KEYRING_FILE` — security review #89: no posture switch is
possible without it); cell salt generated locally (≥ 16 bytes, stays
here); `/etc/tbp/pepd.env` at 0600, owned by the service.

**Command**:

```bash
# /etc/tbp/pepd.env — example values, to adapt to the cell:
#   TBP_CELL_ID=cell-a
#   TBP_SALT=<32-char hex — generated locally, never shared>
#   TBP_KEYRING_FILE=/etc/tbp/keyring.json
#   TBP_POLICY_ID=<sha256 of the bundle, step 4>
#   TBP_REGISTRY_DIR=/var/lib/tbp/cell-a
#   TBP_LISTEN_ADDR=127.0.0.1:8443
#   TBP_OPA_ENDPOINT=http://127.0.0.1:8181/v1/data/tbp/example/action
#   TBP_QUORUM_MIN=2               # k distinct Ed25519 signatures (security
#                                  # review #89 — no longer a name count)
#   TBP_QUORUM_KEYRING_FILE=/etc/tbp/quorum-keyring.json  # controller
#                                  # public keys pinned (§12), same JSON
#                                  # shape as TBP_KEYRING_FILE — required:
#                                  # without it, NO posture switch is possible
#   TBP_CELL_BROKER_SOCKET=/run/tbp/broker.sock  # optional (scale 3): live
#                                  # VERIFIED epoch from the co-located
#                                  # brokerd (step 7), §7.2-§7.3. Absent ⇒
#                                  # FixedEpoch(0), the explicit scale-1
#                                  # choice (single cell, no fencing)
#   TBP_DURABILITY=async-bounded   # default (T38/#71): verdict at
#                                  # acceptance, bounded catch-up;
#                                  # "sync" = former synchronous path
#   TBP_DURABILITY_WINDOW_MS=1000  # opposability window (default 1 s;
#                                  # floor 4 × checkpoint interval)
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s http://127.0.0.1:8443/healthz
curl -s http://127.0.0.1:8443/v1/mode
```

**Observable success criterion**: `/healthz` answers 200;
`GET /v1/mode` returns `{"mode":"monitor"}` — pepd ALWAYS starts in
monitor, the closed switch is governed (step 8 and
[monitor-to-closed.md](monitor-to-closed.md)); on first startup,
`cell_log.key` (0600) and `cell_log.vkey` are created in
`TBP_REGISTRY_DIR` (registry key of THE cell — D97 custody).

**On failure: STOP** — a startup without keyring, without policy ID or
without salt must fail; if it succeeds, the binary is not the one from
the repo. Closed mode IS NOT the goal of this step.

#### Step 7 — Build and start brokerd (full decision chain, T37)

**Verifiable prerequisite**: step 6 green; genesis artefacts (step 1)
in place (`manifest.json` + `epoch0.json` under `$GENESIS_HOME`); PUBLIC
operator keys from the contract store installed (T30 — JSON
`["pubkey_ed25519_hex", …]`, ≥ 1); issuer custody provisioned — EITHER a
DEV issuer seed at 0600 (P1 lab/CI only) OR a real HSM/SoftHSM2 token with
an Ed25519 key pair generated inside it and its PIN at 0600 (security
review #90, point 5 — the private key never leaves the module; see
`src/broker/pkcs11_signer_test.go` for a runnable SoftHSM2 example); broker
salt generated locally (≥ 16 bytes, stays here — the broker's chain is its
OWN, distinct from pepd's).

**Command**:

```bash
go build -o /usr/local/bin/brokerd ./src/broker/cmd/brokerd
/usr/local/bin/brokerd 2>&1 | head -1   # without environment: must refuse

# /etc/tbp/brokerd.env (0600, owned by the service) — example values,
# to adapt to the cell. Issuer custody is EXACTLY ONE of the two blocks
# below — never both, never neither (fail-closed, security review #90.5):
#   TBP_CELL_ID=cell-a
#   TBP_SALT=<32-char hex — salt of the BROKER's chain, generated here>
#   TBP_POLICY_ID=<sha256 of the bundle, step 4>
#   TBP_REGISTRY_DIR=/var/lib/tbp/broker
#   TBP_OPA_ENDPOINT=http://127.0.0.1:8181/v1/data/tbp/example/action
#   TBP_TRANSLATOR=structured
#   # --- custody DEV (lab/CI only) ---
#   TBP_ISSUER_SEED_FILE=/etc/tbp/issuer.seed
#   # --- OR custody HSM (production, §12) ---
#   # TBP_ISSUER_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
#   # TBP_ISSUER_PKCS11_TOKEN_LABEL=cell-a
#   # TBP_ISSUER_PKCS11_KEY_LABEL=issuer-key-1
#   # TBP_ISSUER_PKCS11_PIN_FILE=/etc/tbp/issuer.pin
#   TBP_GENESIS_DIR=<GENESIS_HOME>
#   TBP_QUORUM_MIN=2
#   TBP_CLUSTER_MEMBERS=cell-a,cell-b
#   TBP_OPERATOR_KEYS_FILE=/etc/tbp/operators.json
#   TBP_BROKER_SOCKET=/run/tbp/broker.sock
install -m 0644 src/broker/tbp-brokerd.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tbp-brokerd
curl -s --unix-socket /run/tbp/broker.sock http://localhost/v1/supervision/epoch
```

**Observable success criterion**: the binary builds; launched without
environment, it exits immediately with `brokerd: TBP_CELL_ID requis`
(fail-closed at startup — this refusal IS the criterion); the service is
active; the Unix socket answers in GET only:
`/v1/supervision/epoch` returns epoch 0 and the cell's authority,
`/v1/supervision/arbitration` returns the bundle's `policy_id` (step 4)
and an arbitration queue, `/v1/supervision/stats` the broker's
counters; a POST on these views gets 405. On first startup,
`cell_log.key` (0600) and `cell_log.vkey` are created in
`TBP_REGISTRY_DIR` — the broker's chain is its own (§7.1).

**On failure: STOP** — a brokerd that starts without salt, without
genesis, without OPA or without operator keys is fail-open: fix the
cause, never work around it. A refused `epoch0` means a genesis that
does not match the manifest: redo the distribution (step 1),
never hand-tinker the token.

#### Step 8 — §9.1 measurement points BEFORE any switch (D100)

**Verifiable prerequisite**: steps 6-7 green; the cell has been running in
monitor for an observation window agreed with the supervisor.

**Command**:

```bash
# The T27 harness is the executable reference for the §9.1 measurement points:
go test ./tests/p1_friction/ -run . -count=1
# Cell registry: verified scan (signed checkpoint + Merkle) —
# the independent monitor (deploy/superviseur.md) replays it remotely.
```

**Observable success criterion**: metrics collected (latencies,
would-deny, forwarded); the cell's registry contains
`KindDecision` leaves in monitor (traffic is logged, not blocked).

**On failure: STOP** — no measurement, no closed: the switch is
the [monitor-to-closed.md](monitor-to-closed.md) procedure, with quorum.

## systemd units

Hardening pattern: `src/translator/tbp-translator.service` (T24 —
cap-drop, seccomp `@system-service`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`). The broker's unit is DELIVERED:
`src/broker/tbp-brokerd.service` (T37 — own registry alone writable,
no devices, W^X enforced). Still to adapt on the same pattern:
`pepd.service` and `opa.service`, with `EnvironmentFile=/etc/tbp/pepd.env`
(0600). The `src/translator/audit_confinement.sh` script gives the
post-deployment verification pattern, to adapt to the cell's units.

## System hardening

`config/sysctl/99-tbp-hardening.conf` is a starting point to adapt to the
local kernel and network card — never copied as-is (D99).

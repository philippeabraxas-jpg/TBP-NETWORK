# deploy/monitor-to-closed.md — governed §5.3 switch (T35, issue #61)

_Version française : [monitor-to-closed.fr.md](monitor-to-closed.fr.md)._

**Closed** mode is not installed: it is **earned**. The startup
posture is monitor everywhere (§5.3); the switch requires the §9.1
measurement points installed and fed (D100), an observation window, and
a **quorum** — k Ed25519 signatures from DISTINCT controllers pinned in
`TBP_QUORUM_KEYRING_FILE`, never a self-declared list of names (security
review #89) — a single operator cannot close the network (demonstrated by
the selftest's mono phase: 1 valid signature → 403, k valid signatures →
200).

> MAB: see [checklists/routeur.md](checklists/routeur.md) — MAB is
> a NAC/switch matter (router machine), not a PEP posture. The
> shared doctrine is "never silent": neither an unlogged MAB device,
> nor an untraced switch (`KindTelemetry` leaf, §4.1).

#### Step 1 — Verify that measurement precedes posture (D100)

**Verifiable prerequisite**: all machines in monitor (cellule.md,
serveur.md) for the agreed observation window; the supervisor
collects the cells' leaves (superviseur.md step 4).

**Command**:

```bash
# Executable reference for the §9.1 measurement points (T27):
go test ./tests/p1_friction/ -count=1
# On each PEP:
curl -s http://127.0.0.1:8443/v1/mode    # expected: {"mode":"monitor"}
```

**Observable success criterion**: the §9.1 measurement points (forwarded,
would-deny, denied, p50/p99 latencies) are installed AND fed; each
cell's registry shows `KindDecision` leaves in monitor
(an allow evaluation = verdict + passport, §4.1-bis — measured by the
selftest).

**On failure: STOP** — without fed measurement, no
closed request; "we'll see afterwards" is exactly what §5.3 forbids.

#### Step 2 — Read the observation window

**Verifiable prerequisite**: step 1 green.

**Command**:

```bash
# For each cell: count the window's would-denies (deny verdicts
# logged in monitor). Every would-deny is a flow that WOULD HAVE
# been blocked in closed — each must be explained or explicitly
# accepted before the switch.
go run ./deploy/selftest -phase mono   # shows would-deny on the write witness
```

**Observable success criterion**: list of the window's would-denies,
each classified (legitimate / to fix / rule to adapt in the pilot's
own policies, §14).

**On failure: STOP** — an unexplained would-deny blocks the switch;
closing without explaining it means blinding the network.

#### Step 3 — Request the switch from the quorum (per PEP)

**Verifiable prerequisite**: steps 1-2 green; the controllers are
notified and reachable; `TBP_QUORUM_KEYRING_FILE` on the PEP pins their
public keys; the rollback window (step 4) is decided.

**Command**:

```bash
# The quorum verifier is CRYPTOGRAPHIC (security review #89): k Ed25519
# signatures (TBP_QUORUM_MIN, default 2) from DISTINCT controllers pinned
# in TBP_QUORUM_KEYRING_FILE, each over
# QuorumMessage("mode-closed", expiry) = "TBPQ1" ‖ len(condition) u16 BE
# ‖ condition ‖ expiry u64 BE (pep.QuorumMessage). A body that only
# DECLARES names ("signers": [...], the pre-#89 wire format) is no
# longer even a valid field — it is silently ignored and the request is
# refused for lack of any signature:
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8443/v1/mode \
  -H 'Content-Type: application/json' -d '{"mode":"closed","signers":["op-1","op-2"]}'
# expected: 403 (no signatures at all). One valid signature (k=2) MUST
# also fail — see deploy/selftest/mono.go's mono phase for the full
# worked example (signCtrl helper) that produces real per-controller
# signatures and exercises 1-signature-403 → 2-signature-200:
go run ./deploy/selftest -phase mono
curl -s http://127.0.0.1:8443/v1/mode
```

**Observable success criterion**: 403 without a valid k-of-n proof, 200
with one (`{"mode":"closed","expiry":<unix>,"signatures":[{"key_id":"…",
"signature":"…"}, …]}`, hex-encoded, each signature by a DISTINCT
controller pinned in `TBP_QUORUM_KEYRING_FILE`); `GET /v1/mode` returns
`{"mode":"closed"}`; the switch leaves a `KindTelemetry` leaf in the
cell's registry (counted by the selftest).

**On failure: STOP** — a 200 without a valid quorum proof = broken
verifier: stay in monitor and fix; a 403 with what should be a valid
quorum = insufficient or invalid signatures (wrong key, stale/mismatched
expiry, condition mismatch, or a repeated signer counted once), redo the
request properly.

#### Step 4 — Observe in closed, rollback ready

**Verifiable prerequisite**: step 3 green.

**Command**:

```bash
# In closed, an OPA veto blocks: forwarded=false (demonstrated by the
# selftest's mono phase). Watch denied and the fail-closed alarms (T14).
# Rollback = the reverse governed switch — same k-of-n signed proof
# requirement as step 3, this time over QuorumMessage("mode-monitor", …):
# see deploy/selftest/mono.go for the worked example.
```

**Observable success criterion**: the denies in closed match the
would-denies classified at step 2 — no surprise; the rollback returns
`{"mode":"monitor"}` and leaves its leaf.

**On failure: STOP** — an unexpected deny in closed = immediate
rollback, analysis at the registry, new observation window.

#### Step 5 — Generalize cell by cell

**Verifiable prerequisite**: step 4 stable on the first cell for
the agreed duration.

**Command**:

```bash
# Replay steps 1-4 per cell — never as a wave. §7.2 fencing
# guarantees that a revoked epoch (roster, §7.3) invalidates
# pre-issued tokens by increment: revoking a compromised cell is
# demonstrated by the selftest's fencing phase.
go run ./deploy/selftest -phase fencing
```

**Observable success criterion**: each cell switches to closed with
its quorum, its window, its leaves — the last cell is as
proven as the first.

**On failure: STOP** — a cell that deviates stays in monitor; the
campaign continues elsewhere, that one is handled at the registry.

# deploy/monitor-to-closed.md — governed §5.3 switch (T35, issue #61)

_Version française : [monitor-to-closed.fr.md](monitor-to-closed.fr.md)._

**Closed** mode is not installed: it is **earned**. The startup
posture is monitor everywhere (§5.3); the switch requires the §9.1
measurement points installed and fed (D100), an observation window, and
a **quorum** — a single operator cannot close the network
(demonstrated by the selftest's mono phase: 1 signer → 403, quorum →
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

**Verifiable prerequisite**: steps 1-2 green; the signers are
notified and reachable; the rollback window (step 4) is decided.

**Command**:

```bash
# The current quorum verifier counts signers (TBP_QUORUM_MIN,
# default 2) — quorum crypto is a later phase, the seam is
# in place. 1 signer MUST fail:
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8443/v1/mode \
  -H 'Content-Type: application/json' -d '{"mode":"closed","signers":["op-1"]}'
# expected: 403. Then, quorum assembled:
curl -s -X POST http://127.0.0.1:8443/v1/mode \
  -H 'Content-Type: application/json' \
  -d '{"mode":"closed","signers":["op-1","op-2"]}'
curl -s http://127.0.0.1:8443/v1/mode
```

**Observable success criterion**: 403 without quorum, 200 with;
`GET /v1/mode` returns `{"mode":"closed"}`; the switch leaves a
`KindTelemetry` leaf in the cell's registry (counted by the selftest).

**On failure: STOP** — a 200 without quorum = broken verifier:
stay in monitor and fix; a 403 with quorum = insufficient
signers, redo the request properly.

#### Step 4 — Observe in closed, rollback ready

**Verifiable prerequisite**: step 3 green.

**Command**:

```bash
# In closed, an OPA veto blocks: forwarded=false (demonstrated by the
# selftest's mono phase). Watch denied and the fail-closed alarms (T14).
# Rollback = the reverse governed switch:
curl -s -X POST http://127.0.0.1:8443/v1/mode \
  -H 'Content-Type: application/json' \
  -d '{"mode":"monitor","signers":["op-1","op-2"]}'
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

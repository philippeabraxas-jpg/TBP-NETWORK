# Cell registry — cell log, anchoring, attested state manifest (spec §6, §6.2, §6.3)

Each cell's own hash-chained log (CT/RFC 6962 pattern, Tessera POSIX
driver: one directory per cell log) — the "chaud" (hot) path that doesn't
wait on the master chain — plus everything that makes the cell's own
**state** provable to a third party.

- **Local write, no coordination**: every PEP decision leaf and telemetry
  record lands here first, independent of whether the master chain is
  currently reachable — this is what makes the "tiède" (warm) write to
  the master chain (§6) asynchronous rather than blocking.
- **Disk backpressure — not covered by the spec's PEP-fencing rule, and
  it matters.** The spec bounds the PEP's *authorization* behavior during
  a prolonged partition (fencing by anchoring lag, §6.2 — tokens refused
  past 120 s) but says nothing about the *storage* consequence: during
  that same partition, the local cell keeps writing leaves — every
  refused token is itself a leaf — with nowhere to drain to. An unbounded
  POSIX directory can fill the host disk, which is a second,
  self-inflicted outage layered on top of the network partition.

## Implemented

### Cell log (`cell_log.go`, `leaf.go` — T7)

`CellLog` is an append-only Merkle log per cell, backed by Tessera's POSIX
driver, with signed checkpoints (note format, Ed25519 cell key — §12) that
a third party can verify with the public key alone (`ParseCheckpoint`).
`GenerateCellKey` / `SaveSignerKey` / `LoadSigner` / `NewVerifier` manage
the cell key; the key is generated per-cell and never committed.

Leaves are **hash-only** (§6.2): `Leaf{Kind, CellID, PayloadHash,
Timestamp}` where `PayloadHash = HashPayload(salt, payload)` and the salt
(≥ 16 bytes) never leaves the producer. Leaf kinds:

| kind | meaning | payload record |
|-----:|---------|----------------|
| 1    | PEP decision | `TBPD1` (`src/pep`) |
| 2    | telemetry / alarms (`TBPC1` clock alarm, `TBFF1` fail-closed trip, `TBAD1` durability episode, mode switch) | several, `src/pep` + `async_writer.go` |
| 3    | backpressure engaged | `src/registry` |
| 4    | master-chain anchor (T6) | `TBPA1` (`anchor.go`) |
| 5    | retention purge | — |
| 6    | telemetry alert | — |
| 7    | epoch marker | — |
| 8    | quorum proof | — |
| 9    | promotion | — |
| 10   | plan contract event (T30) | `TBPL1` (`src/pep/plan_contract.go`) |
| 11   | attested state manifest event (T31, §6.3) | `TBPL2` (`manifest.go`, below) |
| 12   | supervision alert — independent monitor's finding (T34, §6.2/§7.1) | `TBPS1` (`src/supervision/alert.go`) |

(`—` = kind reserved in the whitelist; the producing subsystem lands with
its own task. The record prefixes shown are the domain-separation strings
of the hashed payloads, not file formats.)

Marshal and unmarshal whitelists cover exactly kinds 1–12 — a kind unknown
to the binary is rejected on read, never silently dropped (lesson of #65:
both directions must agree).

### Backpressure (`backpressure.go` — T5)

The disk-quota policy described below is enforced as a `BackpressureChecker`
seam wired into `CellLog.Append`: when engaged, appends fail closed; the
stop is itself a leaf and an alarm, same doctrine as the telemetry-cut case
in §5.3 ("classe W" treatment) — not a silent degradation.

### Async bounded durability (`async_writer.go` — T38, issue #71)

The T27 friction spike measured `CellLog.Append` at ~150–250 ms per
decision on the POSIX driver (floor ≈ `CheckpointInterval` 100 ms +
awaiter poll 50 ms — structural, not a tuning artifact): 30–50× the §9.1
tier-1 budget. T38 arbitrates the hot path's durability model as **async
borné** (bounded async); `pepd` selects it by default
(`TBP_DURABILITY=async-bounded`), with `TBP_DURABILITY=sync` restoring the
old fully synchronous behavior.

- **Verdict at acceptance, never fire-and-forget.** `AsyncWriter.Append`
  serializes the leaf, submits it to the Tessera appender (integration is
  sequential, so FIFO order is the log's order), and enqueues the future —
  then returns. The PEP pays ~0.2 ms (in-memory reference), not the
  publication floor. A single tracker goroutine confirms entries in order.
- **Opposability window.** A leaf accepted more than `Window` ago without
  confirmation is a durability cut: the writer trips and every new append
  is refused immediately (`ErrDurabilityCut`) until recovery. Default
  `DefaultOpposabilityWindow` = 1 s (`TBP_DURABILITY_WINDOW_MS`), with a
  hard floor of 4× `CheckpointInterval` — below that, normal publication
  jitter would trip the cut spuriously.
- **Cut = fail-closed, but not `FailClosed.Trip`.** The validator (T9)
  already denies on leaf-write failure, so a cut denies new decisions
  through the existing path with an alarm (`OnTrip`). `Trip` is
  deliberately *not* used: it writes its trip leaf synchronously under the
  same mutex `Gate()` holds, so a stalled publication would freeze the
  entire hot path instead of just refusing it.
- **Recovery is provable.** When the queue drains after a cut, the tracker
  writes a kind-2 telemetry leaf `TBAD1` (episode number, leaves refused
  at cut, cut/recovery timestamps, lag) **synchronously**, then fires
  `OnClear`. The episode — and the count of decisions refused during it —
  is on the log, never silent.
- **Honesty clause.** A process crash inside the window loses at most
  `Window` of accepted-but-unpublished leaves. That is the price of taking
  the publication floor off the hot path; the sync path
  (`CellLog.Append`) remains the writer for administrative leaves (T5 stop
  leaf, T14 alarms, quota, clock, posture) where the decision is already
  made and the write *is* the act.
- **Backlog bound.** The queue is capped (`DefaultAsyncQueueCapacity` =
  8192); a full queue refuses with `ErrDurabilityBacklog` — bounded memory
  before throughput.
- **T5 interplay.** `MonitorOptions.Drain` lets the backpressure monitor
  drain the async writer during `engage()`, after in-flight writes settle
  and before the stop leaf — so the kind-3 backpressure leaf stays
  literally the last leaf of the log.

### Anchoring (`anchor.go`, `tsa.go` — T6)

`Anchorer` periodically anchors the cell log head onto the master chain:
leaf kind 4 (`TBPA1` = `hash(broker_id, tête, TSA)`), RFC 3161 timestamp
via the `TSAClient` seam, anchoring lag exported for the §6.2 fencing rule.

### Attested state manifest (`manifest.go` — T31, §6.3, issue #32)

§6.3: the cell's attested state is `(policy_id, OPA config, broker hash,
local AI container hash, chain head)` — every component change is a
visible, signed, continuous transition; each hash is that of the signed
package (§1).

Two distinct artifacts:

1. **The signed record `TBP-M1`** — published next to the log (same status
   as checkpoints and anchor records); this is what a third-party verifier
   reads **without re-reading the cell's code**. Canonical layout (fixed
   fields, no maps — §11.3 determinism):

   ```
   "TBP-M1" ‖ v(u8=1) ‖ u8 len(cellID) ‖ cellID ‖ epoch(u64 BE) ‖ seq(u64 BE)
            ‖ prevManifestHash(32) ‖ policyID(32) ‖ opaConfigHash(32)
            ‖ brokerHash(32) ‖ aiContainerHash(32) ‖ chainHead(32)
            ‖ issuedAt(u64 BE, unix s)
   ```

   `HashManifest` = SHA-256 of the record (unsigned). The signature is the
   **cell key's** Ed25519 signature over the record bytes directly — the
   same key as the log checkpoints, no new trust root. The published
   artifact (`SignedManifest`) is JSON hex `{record, signature}`, chained
   from genesis (seq 0, prev = 0×32): `VerifyManifestChain(chain,
   verifier)` checks form, signatures, seq/prev chaining, constant cellID,
   non-decreasing epochs. The wire format is frozen by the golden vector
   in `manifest_test.go` (`TestGoldenManifestChain`).

   `chainHead` is captured **just before** the transition leaf is written
   (same pattern as T6 anchoring): it is an audit chronology anchor, not a
   boot invariant — it advances with every leaf, so `CheckBoot` does not
   compare it.

2. **The `TBPL2` leaf (kind 11)** — hash-only (§6.2), in the cell log,
   anchored by T6 like every leaf:

   ```
   "TBPL2" ‖ event(u8) ‖ manifestHash(32) ‖ verdict(u8) ‖ u8 len(reason) ‖ reason
   ```

   Events: `1` boot (genesis or verified start), `2` transition (signed
   component change), `3` refusal (divergent boot, unmeasurable state…).
   Verdict `1` committed, `0` refused. Refusals are leaves too — a refused
   boot is never silent (§4.1).

Fail-closed throughout: no genesis ⇒ no transition; unchanged component
vector ⇒ no transition (a transition attests a *change*); epoch regression
⇒ refused; leaf impossible ⇒ the transition did not happen, alarm (T14).

> Naming: the `Manifest` of `scripts/genesis` (T3) is the **controller
> keys** manifest — a different object with a different role. Here: the
> **state** manifest of the governed stack (glossary §14).

### Measured boot (`measured_boot.go` — §6.3 phase 1)

"Measured boot: the node root is measured by the TPM/HSM at startup."

This package ships the **seam and the fail-closed semantics**, not the
hardware driver — TPM availability on the P1 pilot hardware is a deployment
decision to settle before committing to a mechanism (same dev-stub /
real-hardware split as SoftHSM in T3):

- `RootMeasurer` is the seam; `FileRootMeasurer` is a **dev/test-only**
  implementation (reads a hex hash from a file) — it proves nothing about
  the machine and must never be used in real governance.
- `CheckBoot` confronts the measured root with the provisioned reference
  and the four measured component hashes (`MeasureComponents`) with the
  expected manifest (the last signed manifest). Any divergence — modified
  AI container, modified broker, modified OPA config, unexpected root —
  or any measurement impossibility = boot refused + refusal leaf + T14
  alarm. No expected manifest (no genesis) or no provisioned root
  reference = refused as well: fail-closed covers configuration too (§1).

Integration point: cell startup in `src/pep/cmd/pepd`, **before** the cell
opens its service — wired (security review #96): see
`src/pep/cmd/pepd/measured_boot.go`. Disabled by default
(`TBP_MEASURED_BOOT_MANIFEST_FILE` unset); once configured, the first boot
writes genesis (trust-on-first-use, dev-stub root measurement) and every
later boot calls `CheckBoot` — a deliberate component change must be
declared (`TBP_MEASURED_BOOT_TRANSITION=1`) to re-baseline, never silent.

## Required policy (backpressure)

- A **fixed disk quota** allocated to the local cell log, sized against
  expected leaf rate × the fencing threshold's worst realistic multiple —
  not against "however much disk happens to be free."
- At **80% of that quota**, the local broker stops issuing new
  authorizations (a clean stop, not a crash). This is a second,
  storage-triggered fail-closed condition, distinct from the lag-based
  one in §6.2 (`src/pep/README.md`), and it must fire *before* the host
  disk itself is at risk.
- The stop is itself a leaf (the last thing written before backpressure
  engages) and an alarm to the registry/moniteur — same doctrine as the
  telemetry-cut case in §5.3 ("classe W" treatment): not a silent
  degradation.

## Not implemented here

- **Real TPM/HSM driver** for `RootMeasurer` — pending the P1 pilot
  hardware decision (issue #32 itself defers it); only the seam and the
  dev stub exist.
- **Manifest distribution** beyond T6 anchoring and the published
  `SignedManifest` artifacts (how auditors fetch them is a deployment
  concern, not a format concern).
- Quota sizing against a real P1 pilot leaf rate — see `tests/p1_friction/`
  once it has throughput numbers.

# Cell registry — Tessera POSIX driver (spec §6, §6.2)

Each cell's own hash-chained log (`hash(broker_id, tête, TSA)` per entry,
CT/RFC 6962 pattern) — the "chaud" (hot) path that doesn't wait on the
master chain. Backed by Tessera's POSIX driver: one directory per cell
log.

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

## Required policy

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

## Not implemented here (placeholder)

No code yet. Before writing anything:

1. Confirm Tessera's POSIX driver exposes (or can be wrapped to expose) a
   write-path hook or supports a periodic disk-usage check — the quota
   enforcement above has to live somewhere, either inside the driver's
   write path or as a sidecar watching the directory.
2. Size the quota against a real P1 pilot leaf rate, not a guess — see
   `tests/p1_friction/` once it has throughput numbers.
3. Wire the 80% stop into the same broker code path as the other
   fail-closed conditions in `src/pep/README.md`, so there's one place
   that decides "refuse now," not two independent implementations that
   can drift apart.

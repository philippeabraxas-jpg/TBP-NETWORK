# Acceptance checklist — cell (T35, issue #61)

_Version française : [cellule.fr.md](cellule.fr.md)._

To be checked on the machine, in order. One red box = STOP.

## §12 Cryptography and OPA

- [ ] Ed25519 everywhere — no other curve/algorithm appears in the
      deployed configuration.
- [ ] `capabilities.json` regenerated from THE deployed OPA
      (`policies/gen_capabilities.sh`) — never copied, never committed;
      the 4 forbidden built-ins (`http.send`, `net.lookup_ip_addr`, `time.now_ns`,
      `opa.runtime`) verified absent.
- [ ] OPA runs a bundle compiled WITH these capabilities
      (`opa build --capabilities …`, OPA ≥ 1.0) — no `opa run` on bare
      rules.
- [ ] The negative check passed: an `http.send` rule is
      refused at load time AND at build time.

## §4.1/§6.2 Registry and leaves

- [ ] Tessera registry of THE cell initialized; `cell_log.key` at 0600,
      present only on this machine (D97 custody).
- [ ] Hashing salt ≥ 16 bytes, generated locally, never shared
      (§6.2); the leaves are hash-only.
- [ ] Verified scan replayable (signed checkpoint + Merkle) — the monitor
      replays it remotely (supervisor checklist).

## §5.3 Posture

- [ ] `GET /v1/mode` returns `{"mode":"monitor"}` at startup — always.
- [ ] The closed switch requires the quorum (1 signer → 403, observed).
- [ ] §9.1 measurement points installed and fed BEFORE any
      closed request (D100 — monitor-to-closed.md).

## §7.2 Epoch governance

- [ ] Epoch tracker running (brokerd delivered, cellule.md step 7 —
      T37) with the genesis pubkeys, M-of-N quorum, declared members.
- [ ] `epoch0.json` accepted; `ObservedEpoch` = 0; the cell serves only
      if it is the authority (fail-closed otherwise).
- [ ] Rotation/revocation sequence exercised by the selftest's fencing
      phase on real registries.

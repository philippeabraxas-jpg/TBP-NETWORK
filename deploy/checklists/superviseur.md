# Acceptance checklist — supervisor (T35, issue #61)

_Version française : [superviseur.fr.md](superviseur.fr.md)._

To be checked on the machine, in order. One red box = STOP.

## §12 Genesis

- [ ] Genesis celebrated on HSM (`scripts/genesis`); SoftHSM = DEV
      only, never a governance root.
- [ ] Controller private keys in the HSM, never exported (HSM journal
      as evidence); only pubkeys + `epoch0.json` have left the
      machine, towards the cells, over an authenticated channel (D97 custody).
- [ ] Manifest re-read: M-of-N conforming to the decided governance (2-of-3 at
      the pilot).

## §2/§7.1 Monitor independence

- [ ] The monitor has ITS own key and ITS own log (T34) — distinct from
      any monitored cell.
- [ ] The monitor has no means to WRITE into the monitored chains
      (verified read only: signed checkpoint + Merkle).
- [ ] Alerts (epoch equivocation, anchor delay, continuation
      fraud) arrive at the intended Sink — tested with an alarm
      triggered in the lab.
- [ ] supervisord delivered and running (T37 — superviseur.md step 3;
      structural read-only via ProtectSystem=strict).

## §9.1 Console and indicators

- [ ] Console assembled with its broker counter source (required —
      "broker counter source required §9.1"); `/v1/arbitration`,
      `/v1/epoch`, `/v1/indicators` answer.
- [ ] The indicators are fed BEFORE any closed switch (D100).

## §7.4 Master chain and promotion

- [ ] Bundle anchors and healthy windows published per epoch in the
      master; the window is READ by the cells, never measured by a
      canary.
- [ ] Master partition = promotion refused (fail-closed) — exercised by
      the selftest's fencing phase (`ErrPromotionAnchorUnavailable`,
      `KindPromotion` leaf).

## Network

- [ ] The supervisor joins NO production VLAN (§5.1); its
      channel is supervision.

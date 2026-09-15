# P2 red-team campaign — extended "Michel" scenario (spec §13)

Non-negotiable metric: **zero dangerous action left unlogged** — holes
must be counted, never silently ignored.

## Scenarios to cover (extracted from the spec, to detail when testing)

- [ ] Unknown laptop attempting to join the network (§5.1, NAC switchboard)
- [ ] Direct SFTP bypassing the broker (§5.2, "no direct client → server
      path")
- [ ] USB-key exfiltration (§5.2, hardware — outside network scope,
      compensated by USBGuard/GPO/BIOS-IOMMU)
- [ ] Hotspot / 4G as a bypass channel (§5.2 — not covered by prevention,
      must be detected via resource telemetry)
- [ ] Broker/registry submersion (§7, §8 — a DoS must be alarmed, never a
      silently authorized act)
- [ ] Deceptive plan presented at human arbitration (§4.2 — verify that
      the deviation between the approved plan and actual execution is
      indeed detected)
- [ ] Canary promotion under network partition (§7.4 — the sound window
      must stay anchored in the master chain, never measured by the
      canary itself)
- [ ] Token replay beyond the TTL window (§4.3, jti anti-replay)
- [ ] Telemetry cutoff by an admin under pressure (§5.3 — must require a
      quorum, be signed, alarmed, logged — never a plain silent service
      stop)

Every tested scenario must produce a leaf in the registry — a test that
"passes" without leaving a verifiable trace has proven nothing.

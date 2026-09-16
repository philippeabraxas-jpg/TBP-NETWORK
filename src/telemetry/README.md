# Metadata telemetry — anti-dribble (spec §4.1-bis)

Flow metadata exporters (NetFlow/IPFIX-style) for egress passing through a
passport: bytes per interval, destination, rate. Each record becomes a
leaf in the cell registry.

**Mandatory doctrinal reminder** (§4.1-bis, already corrected once in
v1.4.2 to use the canonical term "passport" rather than "Sésame" — see
`docs/spec-v1.4.6.md` §16): **inspecting the content of passport flows is
prohibited.** Anti-dribble (detecting drip-feed, sub-threshold
exfiltration) relies *exclusively* on metadata post-processing — never on
DPI (deep packet inspection). Any implementation here that touches packet
content rather than metadata is off-doctrine, not just out of scope.

## Not implemented here (placeholder)

- Export format choice: NetFlow v9 or IPFIX (prefer IPFIX, more extensible
  for TBP-specific fields — jti, origin cell).
- Aggregation pipeline before writing to the registry (§4.5: "aggregates +
  corpus hash — content never in the clear" applies here by analogy).
- The "drip-feed" detection itself (thresholds, sliding windows) — an open
  question, no fixed mechanism in the spec beyond the principle.

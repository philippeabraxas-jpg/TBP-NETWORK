# Local PEP (spec §4.1, §4.1-bis, §4.3)

Local policy enforcement point. Responsibilities, per the technical note:

- **Token validation** (§4.1): Ed25519 signature, freshness (TTL
  30–60 s), scope (action + resource), non-consumption.
- **Anti-replay** (§4.3): a bounded-TTL cache of consumed tokens, held
  *locally at each PEP* (not a centralized global cache); every execution
  leaf emitted carries the token's `jti`.
- **Execution-time quota counter** (§4.1-bis): for a passport (opening a
  heavy path), decrements consumed volume — light data-plane state, short
  TTL, one terminator per session. Overrun = clean cutoff + refusal + leaf
  in the cell registry.
- **Fail-closed**: any failure (OPA unreachable, clock unsynchronized
  beyond the NTS threshold §6.2, anchoring lagging past the threshold)
  must result in a refusal, never a silent pass-through.

## Not implemented here (placeholder)

No code yet. Before writing anything:

1. Decide on the language/runtime (the nftables redirect in
   `config/nftables/pep-redirect.nft` assumes a process listening on a
   local port — Go and Rust are the usual choices for a sub-ms-latency
   PEP, cf. target §9 "tier 1 < 2–5 ms").
2. Define the exact schema of the signed token (fields, encoding — JWT/CWT
   or a custom format) BEFORE writing the validator, not after.
3. Write the validator in TDD against the threat↔mechanism matrix
   scenarios (§8): replay, expired token, incorrect scope, exhausted
   passport.

See `tests/p1_friction/` for the latency criteria to respect starting
from the first prototype (friction budget, §9.1).

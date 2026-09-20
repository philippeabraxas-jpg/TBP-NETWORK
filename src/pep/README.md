# Local PEP (spec §4.1, §4.1-bis, §4.3)

Local policy enforcement point. Responsibilities, per the technical note:

- **Token validation** (§4.1): Ed25519 signature, freshness (TTL
  30–60 s), scope (action + resource), non-consumption.
- **Anti-replay** (§4.3): a bounded-TTL cache of consumed tokens, held
  *locally at each PEP* (not a centralized global cache); every execution
  leaf emitted carries the token's `jti`. **Memory-bounded, not just
  TTL-bounded**: a flood of distinct, individually valid tokens can
  exhaust an unbounded or naive LRU cache and evict an unexpired `jti`,
  silently breaking the anti-replay guarantee. Use a fixed-capacity
  structure sized to the passport's max network quota (ring buffer) or a
  sliding-window Bloom filter — never an LRU that evicts under pressure.
  **Fail-closed on saturation**: if the cache reaches its allocated
  capacity, reject new tokens and trip the OPA circuit-breaker
  (`policies/README.md`) instead of evicting older, still-valid `jti`.
- **Clock-status check** (§6.2): NTS (RFC 8915) bounds steady-state
  drift, but says nothing about what the PEP does *during* a resync (an
  NTP step) or a `chrony` loss-of-lock. Poll kernel clock state via
  `adjtimex`/`ntp_adjtime`; if `STA_UNSYNC` is set, do not silently pass
  or silently block — switch to an explicit degraded mode (locally-signed
  only, natural-language input rejected per §4.5's degraded mode, with a
  priority alarm to the registry) until the flag clears.
- **Execution-time quota counter** (§4.1-bis): for a passport (opening a
  heavy path), decrements consumed volume — light data-plane state, short
  TTL, one terminator per session. Overrun = clean cutoff + refusal + leaf
  in the cell registry.
- **Fail-closed**: any failure (OPA unreachable, clock unsynchronized
  beyond the NTS threshold — see clock-status check above, anchoring
  lagging past the threshold §6.2, jti cache saturated — see anti-replay
  above) must result in a refusal, never a silent pass-through.

## Implemented in this package

- **Token validator** (`validator.go`, T9) — CWT + COSE_Sign1 +
  deterministic CBOR, strictly per `token/schema.md` (T8): closed claim
  set, TTL [30, 60] s (§4.1), `kid` resolved in the pinned keyring,
  schema **v1 and v2** accepted (v2 adds the optional claim −8
  `plan_seal`, §4.2 — a v1 token carrying −8 is a schema violation).
  Every decision — allow or deny — leaves a hash-only `KindDecision`
  leaf (§4.1, §6.2): record « TBPD1 », or « TBPD2 » when the token
  carries a plan seal (the seal is *copied* into the execution leaf: the
  PEP holds no plan state, the signed object stays opposable §7.6).
- **Anti-replay cache** (`antireplay.go`, T10) — bounded in memory *and*
  TTL, saturation = refusal, never eviction under pressure.
- **OPA client** (`opa_client.go`, T11) — circuit-breaker 5 ms
  fail-closed (the §12 "OPA circuit-breaker" is not a native OPA
  mechanism; it lives here), decision leaf per evaluation.
- **Passport quota counter** (`quota.go`, T12, §4.1-bis) — bounded
  ledger, overrun = clean cutoff + refusal + leaf.
- **Clock-status check** (`clock.go`, T13, §6.2) — NTS bounds drift;
  `STA_UNSYNC` switches to an explicit degraded mode with alarm, never a
  silent pass or block.
- **Fail-closed point** (`failclosed.go`, T14) — the single
  "refuse now" decision point; every failure above converges here.
- **Listener + monitor/closed mode** (`listener.go`, `mode.go`, T15,
  §5.3) — the process behind `config/nftables/pep-redirect.nft`;
  monitor mode first, the switch to closed is a governed, quorum-proven,
  traced act.
- **Plan contract store** (`plan_contract.go`, T30, §4.2) — "the
  approved plan is a contract: execution is verified against the hash of
  the validated plan; deviation = refusal". Submission seals the plan
  hash (`HashPlan`, domain « TBPC1 » — plan = ordered bounded list of
  steps `(action, resource, params_hash)`, ≤ 64 steps); approval is an
  Ed25519 **operator signature** over « TBPA1 » ‖ planHash ‖ expiry
  (pinned operator keyring, TTL ∈ [60 s, 24 h], default 1 h) —
  "arbitration is a signature, not a read". Execution presents an
  opaque binding (« TBPB1 » ‖ planHash ‖ params, ≤ 4096 o) verified
  against the sealed plan with a **strict cursor**: action, resource and
  parameter hash exact, in order; consumption happens **at issuance**
  (broker step 7 — a cursor shared across PEP replicas would open
  double-spend). Every contract event (submission, approval, refusal,
  consumption, deviation, expiry, revocation) leaves a `KindContract`
  leaf (record « TBPL1 », registry kind 10); a contract event whose leaf
  cannot be written is a system fault (`plan-store-fault`, alarmed) —
  no proof, no contract. The store is bounded (`MaxPending`/
  `MaxApproved`, default 64): saturation = refusal + alarm, never
  eviction (§4.3). Friction: local verification is microseconds, opt-in
  per request (no binding ⇒ no cost).
- **Token schema** (`token/schema.md`, `token/schema.cddl`, T8 + v2
  addendum, T30) — the closed claim set, the golden vector (§9, stays
  v1), and the v2 addendum: claim −8 `plan_seal`, versioning rules
  (emitter always v2, validator accepts v ∈ {1, 2}), and the explicit
  disambiguation between the two "−8" namespaces (COSE protected-header
  `alg` = EdDSA per RFC 9053 vs payload claim −8 = plan seal).

## Latency

See `tests/p1_friction/` for the latency criteria (friction budget,
§9.1): `validator_test.go` enforces the tier-1 budget
(`TestLatencyBudget`); plan-contract verification adds only a local
hash/compare per step, and only for requests that carry a binding.

## PostgreSQL extension (§4.4)

A database-specific in-process PEP, not this generic HTTP/gRPC one — see
[`postgres-extension/README.md`](postgres-extension/) for why it needs two
hooks, not one.

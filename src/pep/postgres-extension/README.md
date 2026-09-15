# PostgreSQL PEP extension (spec §4.4)

In-process mitigation for aliasing (order → effect drift) inside
PostgreSQL: the spec (§4.4) blocks at `post_parse_analyze_hook` rather
than `ExecutorStart_hook` alone, because `ExecutorStart` is post-planning
— a side-effecting function can already have been evaluated by the time
that hook fires.

**`post_parse_analyze` alone is not enough either, for a different
reason.** It fires once, at parse time. For an extended-query-protocol
prepared statement (`PREPARE ...; EXECUTE ... ($1, $2)`) — exactly what
connection poolers and ORMs (SQLAlchemy, Prisma, etc.) do by default to
reuse parse/plan work — the parse tree is built once, with placeholders,
and validated once. Every subsequent `EXECUTE` with concrete parameter
values skips `post_parse_analyze` entirely. A rule validated against
`$1 = 'safe_value'` at prepare time proves nothing about the actual value
bound at execute time.

## Required: hook both, for different purposes

- **`post_parse_analyze_hook`** — structural validation (which tables,
  which operation) against the parse tree, as already specified in §4.4.
- **`ExecutorStart_hook`** — validate a **sealed hash of the finalized
  plan, including bound parameter values** (not placeholders),
  immediately before execution. This closes the prepared-statement/ORM
  gap above.

This does **not** reopen the risk the spec already ruled `ExecutorStart`
out for. That risk was about relying on `ExecutorStart` *alone* to catch
effects already evaluated during planning. Hooking it *in addition to*
`post_parse_analyze`, solely to check bound parameters against an
already-sealed plan hash, doesn't reintroduce it — the structural
decision still happens at parse time; `ExecutorStart` only checks that
the values actually being executed match what was authorized.

## Not implemented here (placeholder)

No code yet. Before writing anything:

1. Confirm which PostgreSQL versions the pilot targets — hook signatures
   have shifted across major versions; pin one before writing C/pgrx code.
2. Decide the sealed-plan-hash format and where it's computed/signed
   (broker? OPA? the extension itself, pre-execution?) — this determines
   whether `ExecutorStart_hook` can validate synchronously within the
   latency budget (§9.1, tier 1 < 2–5 ms) or needs a cached decision.
3. Test explicitly against prepared statements and at least one ORM
   (SQLAlchemy or Prisma) in the P2 red-team scenarios (§13) — the whole
   point of this file is that naive single-hook testing won't catch the
   gap.

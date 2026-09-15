# Latency benchmarks — friction budget (spec §9.1)

The pilot fails if these thresholds don't hold, not only if there's a
functional bug — friction is a founding constraint, not a perf detail to
optimize afterward.

| Measure | Threshold | Source |
|---|---|---|
| Added latency, tier 1 (harmless, read-only) | < 5 ms | §9.1 |
| Tier 1 latency (broad target) | 2–5 ms | §9 |
| Tier 2 latency (to arbitrate, outside human time) | 10–50 ms | §9 |
| Human arbitration rate | < 10% of actions | §9.1 |
| Measured user-experience regression | = 0 (otherwise pilot failure condition) | §9.1 |

## Not implemented here (placeholder)

- Load harness (k6/locust/autocannon depending on `src/pep/`'s final
  stack) measuring the latency added by the PEP alone (excluding
  translator, excluding network) to isolate the variable.
- Tracking over time of the **leading indicators** (§9): arbitration rate
  > 20%, validations < 5 s, uninstrumented holes, TTLs stretching out,
  an exceptions culture — these are the signals of "death by friction"
  (§9, scenario B) before it's too late to correct course.

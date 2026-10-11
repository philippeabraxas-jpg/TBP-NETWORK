# Changelog

All notable changes are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Nothing has been tagged yet: the first release is a
scale 2 release, and its version number is chosen when the tag is created. History before this file is in
`git log` and in the issues.

## [Unreleased]

### Added
- **A DEV-TEST deployment, to run and attack before a production release**
  ([deploy/dev-test/](deploy/dev-test/README.md)). **Not for production**: the keys are thrown away, and the issuer
  key is a seed file, so the cell declares the development sentinel.
  - **Three machines** (`scripts/devtest/site.sh`): M1 the cell (`brokerd`, OPA, an mTLS listener, an agent CA), M2 an
    application server (`pepd` with a real measured boot and no development switch, a small application that acts
    only when `pepd` forwards), M3 an agent. It tests that the whole path works: enrolment by certificate, a
    decision, a signed token, the token checked on another machine, the server's posture closed and reopened by the
    controllers, a restart that comes back refused. M2 and M3 hold no governance key.
  - **`site.sh m1 sign`**: the operators' side as a person does it — the plan is shown in clear, its hash is
    recomputed by `quorumproof planhash` (a plan the broker sealed differently signs nothing), and the operator types
    `sign`. `grant` is `sign --yes`. There is no monitoring or signing console in this release; the pages say so, and [#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329) asks what one should do and show.
  - **`site.sh m1 watch`**: a read-only text view of the cell, a first answer to
    [#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329) that testers can criticise. A source that
    does not answer reads `UNKNOWN` (never green) and the exit status says so; plans waiting are shown by hash,
    because the cell keeps no plan in clear.
  - **Follow a request** (`site.sh m1 trace`, `<role> trace-export`; [#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329)):
    one timeline per request across the three machines — who asked (certificate, address), which component decided
    what and why (reason codes explained in `scripts/devtest/reasons.tsv`), how it ended. `brokerd` writes a decision
    trace behind a new development switch, `TBP_DECISION_TRACE_DEV` (sentinel required, start-up alarm, listed with the
    active development switches); it is written after the verdict and cannot change it. `pepd` is untouched: M2's side
    is the verdict it returned to the application. Requests without a trace id (`curl`) are listed apart.
  - **The live console** (`src/devconsole`, [deploy/dev-test/console.md](deploy/dev-test/console.md), EN/FR;
    [#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329)): after `m1 up`, one address in a browser shows,
    as it happens, the path of each request across the three machines (agent → TLS/identity → cell decision →
    application → `pepd` → executed or rejected, and the component that stopped it, with the reason in words), the state
    of each component (a machine that stops reporting is UNKNOWN, never green) and the latency of every step, each
    measured on one machine with one clock (p50/p95/p99 over the last 500 requests). Runs on M1 by default or on any
    machine (`site.sh console up`); M1 and M2 run a shipper (`devconsole ship`), M3 posts with curl. Read-only, two
    different keys (one opens the page, one lets a machine send), no history. Everything a request carries is shown as
    text: `test_site.sh` opens the page in a real browser with hostile content to check nothing runs.
  - **One machine** (`scripts/devtest/devtest.sh`): the cell alone, for a quick look.
  - Each machine has a `report` (system, versions, timings, counters, latencies, the environment label the tester
    gave; no key, seed, path, address or host name) for testers to send us, and there is a **Dev-test feedback**
    issue template. `test_site.sh` and `test_devtest.sh` run in CI, including every attempt the pages tell testers
    to make.
- Deployment guides for **scale 1** and **scale 2** (English and French), executed by the `scale1` and `scale2`
  phases of `deploy/selftest` ([#86](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/86)).
- **Trust files are measured at every start** by `pepd`, `brokerd` and `anod` (witness signed by the cell key).
  A change needs a quorum proof bound to the attested state and to the target state
  ([#192](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/192),
  [#218](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/218),
  [#236](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/236),
  [#272](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/272)); the scale (`TBP_QUORUM_MIN`,
  topology) and the security switches are attested too
  ([#224](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/224)); the condition to sign is recomputed
  off the controlled machine with `-print-provisioning-condition`
  ([#264](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/264)).
- **`brokerd` attests the rules its own OPA serves**: the signed bundle, the OPA configuration and
  `TBP_POLICY_ID` ([#313](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/313)).
- **Plan approval by k distinct operators** for agents of class F and W (one operator for class I); k is the
  attested quorum, 1 at scale 1 and 2 at scale 2
  ([#196](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/196)). `quorumproof planapprove` takes
  several `-key` and a shared `-expires-at`; new `quorumproof planassemble`.
- Encrypted journal of the plaintext behind the hash-only leaves, verified by `tbp-audit`
  ([#275](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/275),
  [#271](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/271)).
- Operator gestures for plans: recompute a plan hash before signing it with `quorumproof planhash`
  ([#273](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/273)); revoke an approved plan
  ([#244](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/244)).
- **Roles for operator keys**: `operators.json` may give each key only the roles it needs (`approve`, `revoke`,
  `arbitrate`). Approving widens what the cell allows, cutting narrows it, so a night-duty key can revoke a plan or
  rule on a degraded request without being able to approve anything. The plain list of keys still works and gives
  every key every role. A key signing for a role it does not hold is refused with a named reason and a leaf; the
  k signatures of a class-F or class-W approval must come from keys that hold `approve`. `operators.json` is a
  measured trust file: changing it on a cell that already ran takes one transition proof, as for any other.
- **Submitter ≠ approver**: from k = 2, `plan/submit` takes a **signed** submission (`quorumproof plansubmit`; new
  signed message `TBPS1`, bound to the cell and to a short expiry, one use) and the submitter's key can never approve
  that plan. An unsigned submission is refused at k ≥ 2; at k = 1 (one operator does both gestures) it stays open.
  New role `submit` in `operators.json`. **Upgrading** a cell at k = 2: it now needs at least one key that holds
  `submit` and, for each class-F or class-W agent, k approvers other than the submitter — in practice a third operator
  key; `brokerd` refuses to start otherwise and names what is missing. Scale-2 submissions move from a bare `curl` to
  `quorumproof plansubmit`.
- Release machinery: `scripts/release/build.sh` builds `pepd`, `brokerd`, `anod`, `supervisord`,
  `opawatchdog`, `quorumproof` and `tbp-audit` (checked on every pull request); a `vX.Y.Z` tag publishes them
  with SLSA provenance and a CycloneDX SBOM; `SECURITY.md`.

### Changed
- `brokerd` requires `TBP_PROVISIONING_POLICY_BUNDLE` and `TBP_PROVISIONING_OPA_CONFIG` (unless the dev
  opt-out is declared). **Upgrading** a cell that already ran: the first start refuses on the new witness
  entries; one transition proof signed by the attested quorum adopts them.
- When the registry holds a class F or class W agent, at least k distinct keys of `operators.json` must be able to
  approve (and, from k = 2, a submitter apart from them: see "Submitter ≠ approver" above), otherwise `brokerd`
  refuses to start and names what is missing. `plan/approve` accepts `signature` (one) or `signatures` (a list),
  never both.
- **Refusing a degraded request is open to more keys than approving it** ("restricting is not widening"): with
  roles in `operators.json`, a key that holds `revoke` can refuse a degraded request without being able to approve
  it; approving stays with `arbitrate`. Cells on the plain list of keys are unchanged. The new page
  `deploy/governed-acts.md` lists every governed act, which side it is on and what it takes, and what is not
  asymmetric yet (tightening the trust files costs as much as loosening them).
- **Request bodies are decoded strictly** on the data planes and the operator routes
  ([#289](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/289), after
  [#241](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/241) and
  [#274](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/274)): a duplicate key, an unknown field, a
  field name in a different case, content after the document or invalid UTF-8 is refused with HTTP 400 and a
  detail naming the cause, and has no effect. **Upgrading:** an integration that sends an extra field or a
  different case now gets a 400; the exact fields are listed in `deploy/integration-contract.md`, section 5.

- **Closing the network is no longer as hard as reopening it** ("restricting is not widening"): `pepd` accepts
  the switch monitor → closed with `TBP_MODE_RESTRICT_QUORUM_MIN` distinct controller signatures (default 1,
  bounded by k and attested as `mode-restrict-quorum`); reopening and leaving `refused` always need k. A
  reduced-quorum closing leaves its own leaf and raises `mode-closed-reduced-quorum`. Set the variable equal to
  `TBP_QUORUM_MIN` to keep the previous behaviour. **Upgrading:** `pepd`'s first start refuses on
  `security-posture`; one transition proof adopts it.

### Fixed
- `pepd` no longer lists two fail-closed conditions that nothing could trip, `anchor-lag` and
  `registry-disk-high`: a list read by the operator must not suggest a lock that does not exist. A test now
  refuses a registered condition without a detector
  ([#265](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/265)).
- The server guide (`serveur.md`) and `monitor-to-closed.md`, in both languages, called `/v1/mode` and `/healthz` on
  `pepd`'s data port, where they answer 404 since the admin plane moved to a Unix socket (#95), and sent an `epoch`
  field to `/v1/evaluate` that `pepd` now refuses (strict bodies, #289). Found by running the three-machine DEV-TEST.
- Flaky teardown of the Tessera POSIX logs in tests
  ([#266](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/266),
  [#312](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/312)).

### Known limitations of a first scale 2 release
- **No external anchoring** of the registry: the anchoring library exists but no daemon calls it
  ([#265](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/265),
  [#233](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/233),
  [#187](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/187)).
- **One `brokerd`**: if it is down, governed actions stop within about a minute (tokens live 30–60 s). This is
  fail-closed by design; there is no bypass.
- **Changing the rules is a cold, whole-cell operation**: stop every component, change, have the controllers
  sign the condition the daemon prints, restart every component
  ([#315](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/315) plans a single signed act and a
  script).
- **Local administration only**: command-line tools (`quorumproof`, `tbp-audit`) and the read-only
  supervision JSON API; no remote consoles.
- **The translator is the structured v1**: it types the action an agent declares; the natural-language
  translator, plan rewriting and the plan danger score (JEV,
  [#179](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/179)) are not built.
- Binaries are built for linux/amd64 on Debian 12; other targets are untested.

# Changelog

All notable changes are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Nothing has been tagged yet: the first release is a
scale 2 release, and its version number is chosen when the tag is created. History before this file is in
`git log` and in the issues.

## [Unreleased]

### Added
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

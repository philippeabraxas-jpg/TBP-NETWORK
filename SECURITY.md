# Security policy

TBP-NETWORK is security software: a hole in it is a hole in whatever it governs. Please report problems
privately, and we will fix them in the open once they are fixed.

## Supported versions

Before 1.0, only the **latest release** and the `main` branch are supported. There are no backports.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: on the repository page, **Security → Report a vulnerability**.
Please do **not** open a public issue, pull request or discussion for something exploitable.

Helpful in a report: the affected version or commit, the component (`pepd`, `brokerd`, `anod`,
`supervisord`, `quorumproof`, a guide in `deploy/`…), what an attacker needs to start with, how to reproduce,
and the impact you see. A failing test is the best reproduction.

If the reporting form is not available to you, open a public issue titled **Security contact request** with
**no technical detail** and a maintainer will reach out.

What to expect (targets of a small team, not guarantees): an acknowledgement within 7 days, a first
assessment within 30 days, and coordinated disclosure — we will agree a date with you and credit you if you
wish.

## What is in scope

- The code under `src/`, `scripts/`, `policies/` and `tests/`, and the deployment guides in `deploy/`.
- The release artifacts: binaries, their SLSA provenance and the SBOM (see below).

Out of scope:

- `config/` and `lab/`: examples and test topologies that say, file by file, that they must not be deployed
  as they are.
- Behaviour that the documentation already states as a limit. The list is in the README ("Honesty about
  where this stands") and in [CHANGELOG.md](CHANGELOG.md): for example, a single `brokerd` stops governed
  actions when it is down, by design (fail-closed, no bypass). A better design for a documented limit is
  welcome as an ordinary issue.

## How we treat security findings

A security issue stays open until its closure criteria are met and checked, not when a first patch merges.
The criteria are in the [pull request template](.github/pull_request_template.md): a test that fails if the
fix is removed (and a neighbouring case that is still allowed), a review by someone other than the author, up
to date guides in English and French, and what is *not* fixed written down with its own issue.

## Verifying a release

Every release is built by GitHub Actions from a `vX.Y.Z` tag and carries a
[SLSA](https://slsa.dev) v1.0 provenance signed through GitHub's OIDC identity, not by a key stored in this
repository. To check a binary you downloaded:

```bash
# 1. the tool (https://github.com/slsa-framework/slsa-verifier)
# 2. the binary, and the provenance file (*.intoto.jsonl) from the same release page
slsa-verifier verify-artifact ./brokerd \
  --provenance-path <the .intoto.jsonl file of the release> \
  --source-uri github.com/philippeabraxas-jpg/TBP-NETWORK \
  --source-tag vX.Y.Z
```

The binary also records the commit it was built from: `go version -m ./brokerd` prints `vcs.revision`.
The CycloneDX SBOM (`tbp-network.sbom.cdx.json`) is part of the same provenance.

The binaries are built for **linux/amd64** and target **Debian 12**. They are linked dynamically (`brokerd`
needs cgo for PKCS#11 / HSM support); the build fails if a binary would require a glibc newer than Debian 12's.

## Our own supply chain

Workflow actions are pinned by commit SHA (the SLSA generator is pinned by tag, which `slsa-verifier`
requires), workflows run with read-only tokens by default, `govulncheck` runs on every pull request, the
SBOM is generated in CI, and Dependabot proposes dependency updates.

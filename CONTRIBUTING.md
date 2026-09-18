# Contributing to TBP-NETWORK

## Repository status

The code (`config/`, `src/`, `policies/`, `lab/`, `tests/`, `.github/`) is
Apache 2.0 (see `LICENSE`) — external contributions welcome, same as the
documentation (`docs/`, `figs/`, CC BY 4.0, see `docs/LICENSE`). This
repository is largely a skeleton right now (see README's "Current
status"): most of `src/`, `lab/`, and `tests/` are READMEs describing
expected scope, not working code yet — a good entry point for a first
contribution is exactly one of those "not implemented here" sections.
Open an issue first for anything beyond a small, well-scoped change, so
design direction doesn't conflict with an already-planned decision in
the spec.

**`tbp4.2.1/` is a git submodule, not part of this repository's own
code.** It's a pinned pointer into `Responsible-Alliance-Protocol`. Never
send a PR here touching files under `tbp4.2.1/` — it won't merge (the
submodule content isn't tracked by this repo, only its commit pointer
is) and it's the wrong repository for that change regardless: file it
against `Responsible-Alliance-Protocol` directly. A PR here that bumps
the submodule's pinned commit (see README's "Keeping the submodule
current") is welcome, but should say why in the PR description —
"picks up fix X" — not just "update submodule."

Note: the reference specification is `docs/spec-en-v1.0.md` (English);
`docs/spec-v1.4.8.md` is the author's French working note, not the
citable document (see README's "Note on language"). The glossary
(`docs/glossaire.md`) is still French-sourced (§14 of the French doc).
Issues/PRs keeping `spec-en-v1.0.md` and `spec-v1.4.8.md` synchronized
where they diverge, or translating the glossary, are welcome.

## Rules for any change to the specification (`spec-en-v1.0.md` and/or `spec-v1.4.8.md`)

These rules governed `spec-v1.4.4.md` through `spec-v1.4.8.md`; they apply
identically to `spec-en-v1.0.md` now that it is the reference, except
where noted (rule 3). When a substantive change is made to one document,
check whether the other needs the same change — they describe the same
protocol and should not silently diverge on anything normative.

1. **The normalization glossary (§14) is the terminology source of
   truth.** Any change introducing a new concept must either reuse an
   existing canonical term or add it to the glossary — never slip in an
   unmapped synonym in the body text. `docs/glossaire.md` mirrors the §14
   table (with an added English-gloss column for readability, not part of
   the source data) — keep the canonical term / synonyms / definition
   columns in sync between the two whenever either changes.
2. **Any normative reference (RFC, IETF draft, standard) must be verified
   before commit** — number AND title, not just a number that "sounds
   right." A correction of exactly this kind already happened in the
   French doc (see its §16, v1.4.2): RFC 9578 was wrongly cited for
   "Proof of Transit" (it's actually *Privacy Pass Issuance Protocols* —
   "Proof of Transit" was never published as an RFC at all).
3. **Changelog practice differs by document, deliberately.** The French
   doc keeps an explicit §16 table — any version change there must add a
   line, never silently overwrite a previous version's content
   (consistent with its "date your confidence" doctrine, §15). The
   English `spec-en-v1.0.md` has no equivalent §16 table by design (see
   its §13 "Stability policy": git history over the registry's own chain
   is its changelog) — do not add one; track changes via commits instead.
4. **Section numbering**: some sections start at `.2` (§3, §6) rather than
   `.1` — inherited from earlier revisions, not an error to "fix" by
   renumbering the whole document (that would break internal and external
   cross-references). This applies to both documents identically —
   `spec-en-v1.0.md` mirrors the same numbering.

## Reporting an issue

Use the templates in `.github/ISSUE_TEMPLATE/`. For a security issue in
the implementation (not the spec), do not open a public issue — contact
the author directly.

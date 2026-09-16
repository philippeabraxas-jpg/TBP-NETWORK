# Contributing to TBP-NETWORK

## Repository status

The code (`config/`, `src/`, `policies/`, `lab/`, `tests/`, `.github/`) is
under a closed license (see `LICENSE`) — no external contributions
accepted there for now. The documentation (`docs/`, `figs/`) is CC BY 4.0
(see `docs/LICENSE`): corrections and suggestions on the spec, glossary,
or figures are welcome via issue or pull request.

Note: the spec and glossary are currently in French (see README's
"Note on language"). Issues/PRs proposing an English translation, in whole
or in part, are very welcome.

## Rules for any change to `docs/spec-v1.4.5.md`

1. **The normalization glossary (§14) is the terminology source of
   truth.** Any change introducing a new concept must either reuse an
   existing canonical term or add it to the glossary — never slip in an
   unmapped synonym in the body text. `docs/glossaire.md` mirrors the §14
   table (with an added English-gloss column for readability, not part of
   the source data) — keep the canonical term / synonyms / definition
   columns in sync between the two whenever either changes.
2. **Any normative reference (RFC, IETF draft, standard) must be verified
   before commit** — number AND title, not just a number that "sounds
   right." A correction of exactly this kind already happened (see §16,
   v1.4.2): RFC 9578 was wrongly cited for "Proof of Transit" (it's
   actually *Privacy Pass Issuance Protocols* — "Proof of Transit" was
   never published as an RFC at all).
3. **Any version change must add a line to the changelog (§16)**, never
   silently overwrite a previous version's content — consistent with the
   "date your confidence" doctrine in §15.
4. **Section numbering**: some sections start at `.2` (§3, §6) rather than
   `.1` — inherited from earlier revisions, not an error to "fix" by
   renumbering the whole document (that would break internal and external
   cross-references).

## Reporting an issue

Use the templates in `.github/ISSUE_TEMPLATE/`. For a security issue in
the implementation (not the spec), do not open a public issue — contact
the author directly.

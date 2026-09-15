# Translator — runtime hardening (spec §4.5)

The translator (previously called "semantic guard" in upstream documents —
see `docs/glossaire.md`) is the local AI that produces the action actually
executed. This folder covers **runtime hardening** (vLLM/PyTorch), not the
model or the prompts themselves:

- Dedicated non-root process.
- `CAP_DROP_ALL` (dropping all Linux capabilities — to translate into real
  configuration: `CapabilityBoundingSet=` in the systemd unit, or
  `cap_drop: [ALL]` if containerized).
- Strict seccomp.
- **Important reminder from the spec**: `dm-verity` protects the image at
  rest, **not** the runtime surface — don't conflate the two in deployment
  documentation (a verified image can still be compromised once the
  process is running, if the runtime itself isn't confined).

## Not implemented here (placeholder)

- systemd unit for the translator service with the confinement properties
  above (compare with the network PEP in `config/nftables/`, same
  defense-in-depth logic: network AND process).
- **Controlled degradation** (§4.5): if the translator goes down, policy
  is "reject natural language, structured input only, no cloud fallback"
  — to implement as an explicit, tested behavior (see `tests/p2_redteam/`,
  translator-failure scenario), not an accidental side effect of an
  unhandled exception.
- Native per-language corpus (positive/negative) and continuous
  measurement pipeline (FNR < 0.1%, FPR < 2%, §4.5) — open question #4 of
  the spec (§11): "translator: metrics per class, corpus, redundant
  translators — to develop."

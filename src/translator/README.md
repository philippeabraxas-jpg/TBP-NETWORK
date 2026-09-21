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

## Files (T24)

- **`tbp-translator.service`** — hardened systemd unit for a bare-metal
  host: dedicated `tbp-translator` user, empty `CapabilityBoundingSet`,
  `NoNewPrivileges`, `SystemCallFilter=@system-service` (EPERM, native
  arch), `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
  `ProtectSystem=strict`, `PrivateDevices=yes` with explicit
  `DeviceAllow=/dev/nvidia*`, `MemoryDenyWriteExecute=yes`. vLLM serves on
  **loopback only** (`--host 127.0.0.1`) — only the cell broker consumes
  it (§5.1), and it runs with `--enforce-eager` so no JIT needs
  write+execute memory.
- **`seccomp-translator.json`** — allowlist seccomp profile for the
  *containerized* deployment (`docker run --security-opt
  seccomp=seccomp-translator.json …`). `defaultAction: SCMP_ACT_ERRNO`,
  x86_64 native. On bare metal the primary filter is the unit's
  `SystemCallFilter`; this JSON is the container building block and the
  calibration tool.
- **`audit_confinement.sh`** — post-deployment verification (run it in
  deployment CI and after every vLLM/PyTorch upgrade): dedicated non-root
  user, `CapEff == 0`, `NoNewPrivs == 1`, `Seccomp == 2`, systemd unit
  properties, and an **honest network check** — if the process shares the
  host netns, egress denial is *not* proven by confinement: it is carried
  by host nftables (`config/nftables/`) and the audit reports that
  dependency as a warning instead of pretending the hole is closed
  (§5.3). Exit codes: 0 compliant (warnings allowed), 1 violation,
  2 usage/environment error. `--fixture DIR` is the offline/CI seam.
- **`test_audit_confinement.sh`** — offline test of the audit: conforming
  fixture plus one mutation per assertion (every assertion must be able to
  fail — non-vacuity), live checks against `/proc` (unconfined process
  rejected; `setpriv` partially-confined process recognized, missing
  seccomp filter detected). No systemd, no vLLM required.

## Documented exceptions (never silent)

| Directive / choix | État | Justification |
|---|---|---|
| `MemoryDenyWriteExecute=` | **yes** (défaut) | Possible grâce à `--enforce-eager` (pas de JIT Triton/Inductor). Un déploiement qui exige `torch.compile` doit passer à `no`, **documenter la justification** et compenser (profil seccomp conteneur, surveillance renforcée). |
| `PrivateDevices=` + `DeviceAllow=/dev/nvidia*` | actif | PyTorch/CUDA exige les nœuds GPU ; tout le reste de `/dev` est masqué. Déploiement CPU-only : retirer les `DeviceAllow`. |
| `AF_NETLINK` | **exclu** | NCCL (multi-GPU) en aurait besoin ; v1 est mono-nœud. Ne l'ajouter que si NCCL est déployé, et le noter. |
| `ProtectKernelTunnels=` | **absent** | systemd ≤ 252 (bookworm, cible du dépôt) ignore cette clé *en silence* (vérifié par `systemd-analyze verify`) — une directive ignorée en silence est pire qu'une directive absente (§5.3). |
| `ioctl` dans le profil seccomp | autorisé | Résidu assumé : le pilote NVIDIA ne peut pas être filtré plus fin sans casser le driver. Borné par `PrivateDevices` + `DeviceAllow` explicite. |
| `io_uring` | **exclu** | Non requis par la pile de référence ; à réévaluer si vLLM l'adopte. |

## Calibration du filtre d'appels système

Le filtre livré (`@system-service` / allowlist JSON) couvre la pile de
référence vLLM/PyTorch. Pour une pile différente, calibrer **tracé**, puis
resserrer — jamais l'inverse :

1. Conteneur : passer `defaultAction` à `SCMP_ACT_LOG`, rejouer la charge,
   collecter les refus (`audit.log`/journal), retirer ce qui n'est jamais
   utilisé, ne réintégrer que le nécessaire, revenir à `SCMP_ACT_ERRNO`.
2. systemd : ajouter temporairement `SystemCallLog=@all` à l'unit pour
   journaliser les syscalls réellement utilisés pendant un soak test, puis
   resserrer `SystemCallFilter` en conséquence.
3. Rejouer `audit_confinement.sh` après chaque calibration.

## Quality measurement (T26, §4.5)

Continuous translator quality governance — corpus replay + per-class
metrics, blocking in CI, plus stratified human sampling:

- **`measure.py`** — replays the corpus against the deployed scorer
  (`--scorer-cmd`, JSONL seam — shadow mode, never a production decision),
  emits a JSON report (per-class aggregates + deterministic corpus hash,
  **never content**) and exits **1 on any FNR/FPR regression** (CI gate).
  Targets FNR < 0.1 % / FPR < 2 % are **design targets to validate on the
  first native corpus at the pilot (§15)** — reported as such, never as
  established results.
- **`corpus/`** — native per-language corpus structure (`pos`/`neg` per
  class F/I/W/OUT, §5.3) with a deterministic hashing rule and an
  `example/` mini-corpus that exercises the pipeline. The native corpora
  themselves remain **to be constituted at the pilot** (associated
  deliverable).
- **`sample_human.py`** — stratified-by-class sampling of production
  decisions for human review; seeded and manifest-logged so any draw is
  reproducible and auditable.
- **`metrics.go` + `cmd/tmetrics/`** — the registry-side leaf format
  ("TBTM1", KindTelemetry, hash-only §6.2): `tmetrics --report report.json`
  inscribes the measurement into the cell registry (registry keys required,
  never generated there).

CI wiring (workflows are read-only for the agent — copy this step):

```yaml
- name: translator quality gate (T26)
  run: python3 src/translator/measure.py --corpus-dir src/translator/corpus/example \
    --scorer-cmd "<deployed scorer>" --out report.json   # exit 1 = regression
```

## Not implemented here

- **Controlled degradation** (§4.5): if the translator goes down, policy
  is "reject natural language, structured input only, no cloud fallback"
  — the broker-side building block already exists
  (`StructuredTranslator`, `src/broker/`, T33) ; the switchover itself is
  T25 (see `tests/p2_redteam/`, translator-failure scenario), to implement
  as an explicit, tested behavior, not an accidental side effect of an
  unhandled exception.

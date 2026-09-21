# Acceptance checklist — server (T35, issue #61)

_Version française : [serveur.fr.md](serveur.fr.md)._

To be checked on the machine, in order. One red box = STOP.

## Broker-only acceptance

- [ ] The application executes nothing without a `POST /v1/evaluate` verdict
      from ITS cell's PEP — no bypass path exists in the deployed
      business code.
- [ ] `POST /v1/consume` is called at execution time (quota passport
      §4.1-bis); quota overrun cuts cleanly (observed).
- [ ] PostgreSQL: both §4.4(3) hooks of the extension are active —
      structural (`post_parse_analyze`) + frozen-plan seal
      (`ExecutorStart`, bound parameters included).

## §5.3 Posture and measurement

- [ ] pepd starts in monitor; `GET /v1/mode` confirms it.
- [ ] The server cannot switch alone: `POST /v1/mode` without quorum
      → 403 (observed — selftest mono phase).
- [ ] §9.1 measurement points installed and fed in monitor (forwarded,
      would-deny, denied, latencies) — D100 prerequisite to monitor-to-closed.md.

## Host hardening

- [ ] pepd systemd unit on the T24 pattern to adapt
      (`src/translator/tbp-translator.service`): cap-drop, seccomp
      `@system-service`, `ProtectSystem=strict`, `EnvironmentFile` 0600.
- [ ] sysctl hardened from `config/sysctl/99-tbp-hardening.conf`, to
      adapt to the local kernel (D99).
- [ ] No governance key on this machine (D97 custody): neither
      controllers, nor another cell's salt, nor a copied capabilities.json.

## Local registry

- [ ] `cell_log.key` at 0600, created at first startup, only here.
- [ ] `KindDecision` leaves present in monitor (verdict + passport =
      2 leaves per allow evaluation — measured by the selftest).

# Checklist de recette — serveur (T35, issue #61)

_English version: [serveur.md](serveur.md)._

À cocher sur la machine, dans l'ordre. Une case rouge = STOP.

## Acceptation broker-only

- [ ] L'application n'exécute rien sans verdict `POST /v1/evaluate` du PEP
      de SA cellule — aucun chemin de contournement n'existe dans le code
      métier déployé.
- [ ] `POST /v1/consume` est appelé à l'exécution (passeport de quota
      §4.1-bis) ; le dépassement de quota coupe proprement (observé).
- [ ] PostgreSQL : les deux hooks §4.4(3) de l'extension sont actifs —
      structurel (`post_parse_analyze`) + sceau du plan figé
      (`ExecutorStart`, paramètres liés inclus).

## §5.3 Posture et mesure

- [ ] pepd démarre en monitor ; `GET /v1/mode` le confirme.
- [ ] Le serveur ne peut pas basculer seul : `POST /v1/mode` sans quorum
      → 403 (observé — phase mono du selftest).
- [ ] Points de mesure §9.1 installés et alimentés en monitor (forwarded,
      would-deny, denied, latences) — préalable D100 à monitor-to-closed.md.

## Durcissement hôte

- [ ] Unité systemd pepd sur le patron T24 à adapter
      (`src/translator/tbp-translator.service`) : cap-drop, seccomp
      `@system-service`, `ProtectSystem=strict`, `EnvironmentFile` 0600.
- [ ] sysctl durcis à partir de `config/sysctl/99-tbp-hardening.conf`, à
      adapter au noyau local (D99).
- [ ] Aucune clé de gouvernance sur cette machine (custody D97) : ni
      contrôleurs, ni sel d'une autre cellule, ni capabilities.json copié.

## Registre local

- [ ] `cell_log.key` en 0600, créé au premier démarrage, uniquement ici.
- [ ] Feuilles `KindDecision` présentes en monitor (verdict + passeport =
      2 feuilles par évaluation allow — mesuré par le selftest).

# Checklist de recette — cellule (T35, issue #61)

_English version: [cellule.md](cellule.md)._

À cocher sur la machine, dans l'ordre. Une case rouge = STOP.

## §12 Cryptographie et OPA

- [ ] Ed25519 partout — aucune autre courbe/algorithme n'apparaît dans la
      configuration déployée.
- [ ] `capabilities.json` régénéré depuis L'OPA déployé
      (`policies/gen_capabilities.sh`) — jamais copié, jamais commité ;
      les 4 interdits (`http.send`, `net.lookup_ip_addr`, `time.now_ns`,
      `opa.runtime`) vérifiés absents.
- [ ] OPA exécute un bundle compilé AVEC ces capabilities
      (`opa build --capabilities …`, OPA ≥ 1.0) — pas de `opa run` sur les
      règles nues.
- [ ] La vérification négative est passée : une règle `http.send` est
      refusée au chargement ET au build.

## §4.1/§6.2 Registre et feuilles

- [ ] Registre tesseraire de LA cellule initialisé ; `cell_log.key` en 0600,
      présent uniquement sur cette machine (custody D97).
- [ ] Sel de hachage ≥ 16 octets, généré localement, jamais partagé
      (§6.2) ; les feuilles sont hash-only.
- [ ] Scan vérifié rejouable (checkpoint signé + Merkle) — le moniteur le
      rejoue à distance (checklist superviseur).

## §5.3 Posture

- [ ] `GET /v1/mode` rend `{"mode":"monitor"}` au démarrage — toujours.
- [ ] La bascule closed exige le quorum (1 signataire → 403, observé).
- [ ] Points de mesure §9.1 installés et alimentés AVANT toute demande de
      closed (D100 — monitor-to-closed.md).

## §7.2 Gouvernance d'époque

- [ ] Tracker d'époques en service (brokerd livré, cellule.md étape 7 —
      T37) avec les pubkeys de la genèse, quorum M-of-N, membres déclarés.
- [ ] `epoch0.json` accepté ; `ObservedEpoch` = 0 ; la cellule ne sert que
      si elle est l'autorité (fail-closed sinon).
- [ ] Séquence rotation/révocation éprouvée par la phase fencing du
      selftest sur registres réels.

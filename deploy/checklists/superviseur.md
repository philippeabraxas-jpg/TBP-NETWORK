# Checklist de recette — superviseur (T35, issue #61)

À cocher sur la machine, dans l'ordre. Une case rouge = STOP.

## §12 Genèse

- [ ] Genèse célébrée sur HSM (`scripts/genesis`) ; SoftHSM = DEV
      uniquement, jamais racine de gouvernance.
- [ ] Clés privées des contrôleurs dans le HSM, jamais exportées (journal
      HSM à l'appui) ; seules pubkeys + `epoch0.json` ont quitté la
      machine, vers les cellules, par canal authentifié (custody D97).
- [ ] Manifest relu : M-of-N conforme à la gouvernance décidée (2-of-3 au
      pilote).

## §2/§7.1 Indépendance du moniteur

- [ ] Le moniteur a SA propre clé et SON propre log (T34) — distincts de
      toute cellule surveillée.
- [ ] Le moniteur n'a aucun moyen d'ÉCRIRE dans les chaînes surveillées
      (lecture vérifiée uniquement : checkpoint signé + Merkle).
- [ ] Les alertes (équivoque d'époque, retard d'ancre, fraude de
      continuation) arrivent sur le Sink prévu — testé par une alarme
      provoquée en lab.
- [ ] Assemblage documenté (trou #74 : pas de binaire supervisord —
      patron superviseur.md étape 3).

## §9.1 Console et indicateurs

- [ ] Console assemblée avec sa source de compteurs broker (requis —
      « source de compteurs broker requise §9.1 ») ; `/v1/arbitration`,
      `/v1/epoch`, `/v1/indicators` répondent.
- [ ] Les indicateurs sont alimentés AVANT toute bascule closed (D100).

## §7.4 Master chain et promotion

- [ ] Ancres de bundles et fenêtres saines publiées par époque dans le
      master ; la fenêtre est LUE par les cellules, jamais mesurée par un
      canari.
- [ ] Partition du master = promotion refusée (fail-closed) — éprouvé par
      la phase fencing du selftest (`ErrPromotionAnchorUnavailable`,
      feuille `KindPromotion`).

## Réseau

- [ ] Le superviseur ne rejoint AUCUN VLAN de production (§5.1) ; son
      canal est la supervision.

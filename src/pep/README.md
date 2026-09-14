# PEP local (spec §4.1, §4.1-bis, §4.3)

Point d'application de politique local. Responsabilités, d'après la note
technique :

- **Validation de token** (§4.1) : signature Ed25519, fraîcheur (TTL
  30–60 s), portée (action + ressource), non-consommation.
- **Anti-rejeu** (§4.3) : cache de tokens consommés à TTL borné, tenu
  *localement à chaque PEP* (pas un cache global centralisé) ; chaque
  feuille d'exécution émise porte le `jti` du token.
- **Compteur de quota à l'exécution** (§4.1-bis) : pour un passeport
  (ouverture de chemin lourd), décrémente le volume consommé — état
  data-plane léger, TTL court, un seul terminateur par session. Dépassement
  = coupure propre + refus + feuille dans le registre de cellule.
- **Fail-closed** : toute panne (OPA injoignable, horloge non synchronisée
  au-delà du seuil NTS §6.2, ancrage en retard > seuil) doit se traduire
  par un refus, jamais par un laisser-passer silencieux.

## Non implémenté ici (placeholder)

Aucun code pour l'instant. Avant d'écrire quoi que ce soit :

1. Décider du langage/runtime (le nftables redirect de
   `config/nftables/pep-redirect.nft` suppose un process qui écoute sur un
   port local — Go et Rust sont les choix habituels pour un PEP à latence
   sub-ms, cf. cible §9 "tier 1 < 2–5 ms").
2. Définir le schéma exact du token signé (champs, encodage — JWT/CWT ou
   format maison) AVANT d'écrire le validateur, pas après.
3. Écrire le validateur en TDD contre les scénarios de la matrice
   menaces↔mécanismes (§8) : rejeu, token expiré, portée incorrecte,
   passeport épuisé.

Voir `tests/p1_friction/` pour les critères de latence à respecter dès le
premier prototype (budget de friction, §9.1).

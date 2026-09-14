# Télémétrie de métadonnées — anti-dribble (spec §4.1-bis)

Exportateurs de métadonnées de flux (style NetFlow/IPFIX) pour l'egress
passant par un passeport : octets par intervalle, destination, rythme.
Chaque enregistrement devient une feuille dans le registre de cellule.

**Rappel doctrinal impératif** (§4.1-bis, déjà corrigé une fois en v1.4.2
pour utiliser le terme canonique "passeport" plutôt que "Sésame" — voir
`docs/spec-v1.4.2.md` §16) : **l'inspection du contenu des flux du
passeport est proscrite.** L'anti-dribble (détection d'exfiltration
goutte-à-goutte, sous-seuil) repose *exclusivement* sur le post-traitement
des métadonnées — jamais sur du DPI (deep packet inspection). Toute
implémentation ici qui toucherait au contenu des paquets plutôt qu'à leurs
métadonnées est hors-doctrine, pas juste hors-scope.

## Non implémenté ici (placeholder)

- Choix du format d'export : NetFlow v9 ou IPFIX (préférer IPFIX, plus
  extensible pour les champs propres à TBP — jti, cellule d'origine).
- Pipeline d'agrégation avant écriture au registre (§4.5 : "agrégats +
  hash du corpus — contenu jamais en clair" s'applique par analogie ici).
- Détection du "goutte-à-goutte" elle-même (seuils, fenêtres glissantes) —
  question ouverte, pas de mécanisme figé dans la spec au-delà du principe.

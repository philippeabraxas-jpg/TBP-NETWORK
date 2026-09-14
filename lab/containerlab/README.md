# Topologie de test L2/L3 (containerlab)

Rien de défini encore. Objectif d'après la spec : émuler la topologie du
pilote P1 (§13) — 1 VLAN serveurs, routeur Debian, 2 cellules, NAC
802.1X — sans matériel physique, pour tester `config/nftables/`,
`config/freeradius/` et le comportement fail-closed (§5.3) avant tout
déploiement réel.

À définir avant d'écrire un fichier `.clab.yml` :
- Nœuds : combien de "postes" simulés, un switch (ou une image le simulant,
  ex. `ceos`/`cvx` selon disponibilité), le routeur Debian avec les
  configs de `config/`.
- Scénario minimal à valider en premier : un poste authentifié 802.1X
  atteint le broker ; un poste non enregistré atterrit en VLAN captif —
  c'est le test le plus basique du "mur et aiguillage" (§5.1).

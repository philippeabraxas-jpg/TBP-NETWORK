# Figures référencées par `docs/spec-v1.4.2.md`

Aucun fichier image n'existe encore dans ce dossier — les six figures
suivantes sont référencées par la note technique mais restent à produire.
Ce manifeste liste ce que chacune doit montrer, d'après le texte qui
l'entoure dans la spec, pour que quiconque les dessine (ou les génère) parte
du bon contenu sans avoir à relire tout le document.

| Fichier | Section | Contenu attendu |
|---|---|---|
| `fig1_chaine.png` | §0 Résumé | La chaîne de gouvernance TBP de bout en bout : agent → traducteur → OPA (décision) → PEP (exécution) → registre (preuve) — le schéma d'ensemble auquel tout le reste renvoie. |
| `fig2_handshake.png` | §3 Handshake inter-entités | Les trois preuves du handshake en séquence : policy_id (règles), preuve de consistance O(log n) (historique), nonce → cycle OPA → feuille → signature HSM (vivacité). |
| `fig3_reseau.png` | §5.1 Le mur et l'aiguillage | Topologie réseau : NAC en aiguillage, VLAN broker vs VLAN captif, mur serveur (aucun chemin direct client→serveur), EAP-TLS partageant la PKI du handshake. |
| `fig4_registre.png` | §6 Registre à deux niveaux | Chaîne de cellule (chaud) → inscription périodique dans la chaîne maîtresse (motif CT/RFC 6962) → ancrage externe (froid). |
| `fig5_passeport.png` | §4.1-bis Passeports à capacité bornée | Séparation des températures : compteur au PEP/terminateur (exécution) vs enveloppe d'egress au broker (émission), avec la télémétrie de métadonnées en sortie. |
| `fig6_cles.png` | §7 Cluster : cellules, époques, miroirs, canari | Hiérarchie de clés et de temps : contrôleurs (m-of-n, HSM) → jeton d'époque (TTL) → clés de cellule → tokens d'action (TTL court). |

Format suggéré : SVG source versionné (`figs/src/`) + export PNG ici, pour
rester éditable sans dépendre d'un outil propriétaire. Palette et style :
voir la mention « palette harmonisée » du changelog v1.4.1 (§16) — à définir
si aucune charte n'existe déjà ailleurs.

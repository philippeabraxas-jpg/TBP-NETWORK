# Traducteur — durcissement runtime (spec §4.5)

Le traducteur (anciennement appelé "garde sémantique" dans des documents
amont — voir `docs/glossaire.md`) est l'IA locale qui produit l'action
réellement exécutée. Ce dossier couvre le **durcissement runtime**
(vLLM/PyTorch), pas le modèle ni les prompts eux-mêmes :

- Processus non-root dédié.
- `CAP_DROP_ALL` (retrait de toutes les capacités Linux — à traduire en
  configuration réelle : `CapabilityBoundingSet=` dans l'unité systemd, ou
  `cap_drop: [ALL]` si conteneurisé).
- Seccomp strict.
- **Rappel important de la spec** : `dm-verity` protège l'image au repos,
  **pas** la surface runtime — ne pas confondre les deux dans la
  documentation de déploiement (une image vérifiée peut quand même être
  compromise une fois le process démarré, si le runtime n'est pas
  lui-même confiné).

## Non implémenté ici (placeholder)

- Unité systemd du service traducteur avec les propriétés de confinement
  ci-dessus (comparer avec le PEP réseau de `config/nftables/`, même
  logique de défense en profondeur : réseau ET process).
- **Dégradé contrôlé** (§4.5) : si le traducteur tombe, la politique est
  "rejet du langage naturel, structuré seulement, aucun fallback cloud" —
  à implémenter comme un comportement explicite et testé (voir
  `tests/p2_redteam/`, scénario de panne du traducteur), pas une
  conséquence accidentelle d'une exception non gérée.
- Corpus natif par langue (positif/négatif) et pipeline de mesure continue
  (FNR < 0,1 %, FPR < 2 %, §4.5) — question ouverte #4 de la spec (§11) :
  "métriques par classe, corpus, traducteurs redondants — à développer."

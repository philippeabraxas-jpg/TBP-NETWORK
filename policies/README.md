# Policies — OPA / Rego (spec §12 checklist)

## `capabilities.json` — à générer, pas à copier

Pas de `capabilities.json` fourni dans ce dossier : le contenu réel dépend
de la version d'OPA effectivement déployée (la liste des built-ins change
d'une version à l'autre), donc un fichier écrit à la main ici serait soit
faux, soit obsolète dès la prochaine mise à jour d'OPA — un risque de
sécurité pire que l'absence de fichier (un `http.send` qu'on croit bloqué
alors qu'il ne l'est pas plus).

Séquence correcte, à documenter dans le pipeline de déploiement :

```sh
# 1. Générer la liste complète des built-ins de LA version d'OPA déployée
opa capabilities > policies/capabilities.json

# 2. Retirer manuellement les built-ins qui violent la doctrine (spec §12) :
#    - http.send            (aucun appel réseau sortant depuis une règle)
#    - net.lookup_ip_addr   (même raison)
#    - time.now_ns          (le temps vient du broker/NTS, pas de l'horloge locale d'OPA — §6.2)
#    - opa.runtime          (sauf usage déjà audité et justifié, ex. lire un
#                            jeton d'environnement — jamais pour de l'I/O)

# 3. Démarrer OPA avec ce fichier de capacités restreint :
opa run --server --capabilities policies/capabilities.json ...
```

**Circuit-breaker OPA (mentionné §0/§12)** : ce n'est pas un mécanisme natif
d'OPA — il n'existe rien d'intégré au moteur Rego qui coupe une évaluation
à 5 ms. C'est une propriété à implémenter côté appelant (le PEP/broker,
voir `src/pep/`) : timeout strict sur l'appel à OPA, **fail-closed** (deny)
si dépassé. À ne pas présenter comme une garantie d'OPA lui-même dans la
documentation ou le code — même principe que le préfixe honnête déjà établi
ailleurs dans l'écosystème TBP pour ne jamais laisser croire à une
vérification qui n'existe pas.

## `rego/` — exemples de politiques

Voir [`rego/README.md`](./rego/) pour les squelettes de départ (defaut-deny,
structure minimale conforme à la doctrine §1). Ce sont des **exemples
illustratifs** pour amorcer les règles propres du pilote (§14 : « règles
propres »), pas une politique de référence à déployer telle quelle.

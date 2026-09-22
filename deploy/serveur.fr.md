# deploy/serveur.md — machine « serveur » (T35, issue #61)

_English version: [serveur.md](serveur.md)._

Le serveur héberge l'application (PostgreSQL, service métier…). Sa
doctrine : **acceptation via le broker de SA cellule uniquement** — le
serveur ne fait confiance ni au réseau, ni à un autre PEP, ni à lui-même.
Le PEP `pepd` tourne ici (ou sur la cellule selon le partitionnement
choisi) ; les instructions ci-dessous supposent pepd sur le serveur.

#### Étape 1 — Prérequis machine

**Prérequis vérifiable** : étapes communes de [README.md](README.fr.md)
vertes ; la cellule de rattachement est installée
([cellule.md](cellule.fr.md)) et en monitor ; la matrice de custody (D97)
est respectée — aucune clé de gouvernance ne transite par ce serveur.

**Commande** :

```bash
go version
getent hosts cell-a   # ou IP : joignabilité de la cellule de rattachement
```

**Critère de succès observable** : go ≥ 1.24 ; la cellule répond au nom
ou à l'IP prévue.

**En cas d'échec : STOP** — pas de cellule joignable, pas de PEP utile ;
finir la cellule d'abord.

#### Étape 2 — Installer et démarrer pepd (monitor, §5.3)

**Prérequis vérifiable** : étape 1 verte ; keyring, policy ID et sel
préparés SELON cellule.md étapes 4-6 (sel local ≥ 16 octets, jamais
partagé ; `/etc/tbp/pepd.env` en 0600).

**Commande** :

```bash
go build -o /usr/local/bin/pepd ./src/pep/cmd/pepd
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s http://127.0.0.1:8443/v1/mode
```

**Critère de succès observable** : `{"mode":"monitor"}` ; `/healthz` 200 ;
registre tessera initialisé dans `TBP_REGISTRY_DIR` (clé de cellule
locale, 0600).

**En cas d'échec : STOP** — toute absence d'environnement (`TBP_SALT`,
`TBP_KEYRING_FILE`, `TBP_POLICY_ID`) DOIT faire échouer le démarrage ; un
pepd qui démarre incomplet est un faux pepd.

#### Étape 3 — Brancher l'application sur le PEP (acceptation broker-only)

**Prérequis vérifiable** : étape 2 verte.

**Commande** :

```bash
# PostgreSQL : l'extension applique les deux hooks §4.4(3) —
# structurel (post_parse_analyze) + sceau du plan figé (ExecutorStart) :
ls src/pep/postgres-extension/
# L'app métier appelle POST /v1/evaluate AVANT d'exécuter, et
# POST /v1/consume à l'exécution (passeport de quota §4.1-bis).
curl -s -X POST http://127.0.0.1:8443/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"token":"<cwt base64>","action":"read","resource":"doc-1","epoch":0}'
```

**Critère de succès observable** : le verdict JSON rend `allow`, `mode`
(monitor), `forwarded` ; en monitor, même un deny est `forwarded=true`
(log only) avec `reason` explicite — le témoin de la phase mono du
selftest montre `opa-deny`.

**En cas d'échec : STOP** — un verdict illisible ou un HTTP non-200 n'est
pas un deny exploitable ; corriger la chaîne avant de poursuivre.

#### Étape 4 — Durcissement de l'hôte

**Prérequis vérifiable** : étapes 2-3 vertes.

**Commande** :

```bash
# Point de départ à adapter au noyau local (D99) — jamais copié tel quel :
less config/sysctl/99-tbp-hardening.conf   # à adapter avant application
# Patron d'unité durcie (T24) à adapter pour pepd.service :
less src/translator/tbp-translator.service
```

**Critère de succès observable** : l'unité pepd est en place avec
cap-drop, seccomp `@system-service`, `ProtectSystem=strict`,
`EnvironmentFile` en 0600 ; `audit_confinement.sh` (motif T24, à adapter)
ne rapporte aucun écart.

**En cas d'échec : STOP** — un PEP non confiné est une surface ; corriger
l'unité avant d'ouvrir le service aux applications.

#### Étape 5 — Mesures §9.1 en monitor, puis demande de bascule

**Prérequis vérifiable** : étapes 2-4 vertes ; fenêtre d'observation
monitor convenue écoulée ; le superviseur collecte les feuilles
(deploy/superviseur.md).

**Commande** :

```bash
# Compteurs exposés par le listener (GET /v1/stats si câblé, sinon
# registre) : forwarded, would-deny, denied, latences. Référence
# exécutable des points de mesure : tests/p1_friction/ (T27).
curl -s http://127.0.0.1:8443/healthz
```

**Critère de succès observable** : les points de mesure §9.1 sont
installés ET alimentés en monitor — c'est un préalable de
[monitor-to-closed.md](monitor-to-closed.fr.md) (D100), pas une option.

**En cas d'échec : STOP** — pas de mesure, pas de demande de closed. La
bascule se décide au quorum (§5.3), jamais en local sur ce serveur.

## Ce que ce serveur ne fait JAMAIS

- accepter un jeton sans passer par le PEP/broker de sa cellule ;
- héberger une clé de contrôleur, le sel d'une autre cellule, ou un
  capabilities.json copié d'un autre déploiement (il se régénère depuis
  L'OPA déployé — voir cellule.md étape 3, et config/ reste à adapter) ;
- basculer lui-même en closed : `POST /v1/mode` exige le quorum (403
  sinon — démontré par la phase mono du selftest).

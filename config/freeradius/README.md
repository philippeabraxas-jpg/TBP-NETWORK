# FreeRADIUS — 802.1X / EAP-TLS (spec §5.1)

Le NAC est un **aiguillage**, pas un mur : authentifié (802.1X, EAP-TLS) →
VLAN donnant accès au broker ; inconnu → VLAN captif dont la seule route est
l'enrôlement ou le broker-forcé. **EAP-TLS doit réutiliser la même PKI que
le handshake TBP (§3)** — une seule infrastructure d'identité, pas deux.

## Ce qui manque encore ici

Aucune config FreeRADIUS n'est fournie pour l'instant — ce dossier est un
point d'ancrage, pas un déploiement prêt à l'emploi. À produire avant le
pilote P1 (§13) :

- `clients.conf` : déclaration des switchs/AP comme clients RADIUS
  (secrets partagés — jamais commités, voir `.gitignore` racine).
- `sites-available/tbp-eap-tls` : site dédié EAP-TLS, certificats émis par
  la même autorité que le handshake (§3), CA privée dédiée au pilote,
  jamais la CA de test FreeRADIUS livrée par défaut.
- `mods-available/eap` : forcer `tls-config` sur la CA du pilote,
  désactiver les méthodes EAP autres que TLS (pas de PEAP/MSCHAPv2 en
  parallèle — une seule voie d'authentification, cohérent avec la
  doctrine "jamais par nom, toujours par signature", §1).

## Points de configuration critiques (doctrine §5.3)

- **Fail-closed obligatoire** : le comportement par défaut de FreeRADIUS
  sur un rejet ou un timeout est de refuser — ne **jamais** configurer de
  VLAN de repli "ouvert" en cas d'échec d'authentification. Le texte de
  référence appelle ça le "défaut fail-open souvent implicite du RADIUS" :
  il doit être forcé fail-closed **côté switch** (assignation VLAN par
  défaut = VLAN captif, jamais un VLAN de confiance), pas seulement côté
  serveur RADIUS.
- **MAB (MAC Authentication Bypass)** : si utilisé pour des périphériques
  IoT ne supportant pas 802.1X, il doit rester un **canal instrumenté**
  (§5.3) — VLAN IoT dédié, jamais silencieux, télémétrie alimentant le
  registre comme tout "trou" du mur.
- **Déploiement progressif** : mode `monitor` (auth loggée, pas encore
  appliquée) avant `closed` (VLAN réellement contraint) — jamais l'inverse
  en production. Pas de VLAN assigné par RADIUS en v1 (`tunnel-private-group-id`
  désactivé initialement) — le NAC ne fait qu'aiguiller authentifié/non
  authentifié dans un premier temps, la granularité de VLAN par profil
  vient après validation du pilote.

## Vérification OCSP/CRL

Un OCSP ou CRL injoignable ne doit **jamais** être un soft-fail silencieux
(cert accepté par défaut) — router vers un VLAN de remédiation avec un
retour visible à l'utilisateur, jamais un blocage muet ni un laisser-passer
muet.

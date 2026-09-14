# TBP-NETWORK

Implémentation réseau du **Teleological Bounding Protocol (TBP)** —
gouvernance d'actions attestée pour agents IA en réseau, du petit
déploiement jusqu'à l'échelle WWW.

> *« Le contrôle d'accès existant décide si tu entres ; TBP décide ce que tu
> peux faire une fois dedans — et le prouve. On gouverne les capacités, pas
> les modèles. »*

## Commencer ici

La spécification complète est **[`docs/spec-v1.4.2.md`](docs/spec-v1.4.2.md)** —
c'est la source de vérité pour toute décision de conception ou de
configuration dans ce dépôt. Ce README ne résume que ce qu'il faut pour
s'orienter ; en cas de doute, la spec fait foi.

Repères utiles pour la lire :
- **§1 Doctrine** — les huit règles non négociables.
- **§13 Séquence d'implémentation** — l'ordre à suivre (HSM → OPA → PEP →
  NAC → traducteur), et le scope exact du pilote P1.
- **§9.1 Budget de friction** — les seuils de latence et d'arbitrage qui
  font qu'un déploiement TBP est réussi ou non ; à garder sous les yeux à
  chaque décision de configuration.
- **[`docs/glossaire.md`](docs/glossaire.md)** — un terme canonique par
  concept ; à utiliser partout dans le code et la doc de ce dépôt (voir
  `CONTRIBUTING.md`).

## Structure du dépôt

```
docs/                 Spécification (spec-v1.4.2.md), glossaire, audits
figs/                  Figures référencées par la spec (voir MANIFEST.md — aucune n'existe encore)
policies/
├── README.md          Comment générer capabilities.json correctement
└── rego/               Exemples illustratifs de politiques Rego
config/
├── nftables/           Redirection PEP local (§4.1)
├── freeradius/          802.1X / EAP-TLS (§5.1)
└── sysctl/               Durcissement kernel générique
src/
├── pep/                 Point d'application de politique local (§4.1, §4.1-bis, §4.3)
├── telemetry/            Métadonnées de flux, anti-dribble (§4.1-bis)
└── translator/            Durcissement runtime du traducteur (§4.5)
lab/                    PoC docker-compose + topologie containerlab (à définir)
tests/
├── p1_friction/         Seuils de latence à respecter (§9.1)
└── p2_redteam/           Scénarios d'attaque à couvrir (§13)
.github/                Templates d'issue, CI (lint Rego + nftables)
```

**État actuel : essentiellement un squelette.** La spec est corrigée et
complète ; `config/` et `policies/` contiennent des points de départ
concrets ; `src/`, `lab/` et `tests/` sont pour l'instant des README
décrivant le scope attendu (voir §13 pour l'ordre dans lequel les remplir).
Ne pas déployer `config/` tel quel — chaque fichier le dit explicitement,
mais autant le répéter ici.

## Indications de configuration — par où commencer

D'après la séquence d'implémentation (§13) et le scope du pilote P1
(§13, §9.1 : 1 VLAN serveurs, routeur Debian, 2 cellules, 802.1X, registre
central, régression utilisateur mesurée = 0) :

1. **Genèse et clés** (§7.2, §3.2) — avant tout le reste : cérémonie de
   genèse signée par le quorum de contrôleurs (m-of-n, HSM), ancrée
   hors-bande. Rien dans ce dépôt ne remplace cette étape ; elle est
   procédurale, pas du code.
2. **OPA** — installer, générer `policies/capabilities.json` selon
   [`policies/README.md`](policies/README.md) (retirer `http.send` et
   `time.now_ns` avant tout déploiement, jamais après), démarrer avec
   `lab/docker-compose.yml` pour itérer sur les règles en local.
3. **PEP** — le premier périmètre réellement gouverné (§13). Lire
   [`src/pep/README.md`](src/pep/README.md) pour les décisions à prendre
   avant d'écrire du code, et [`config/nftables/pep-redirect.nft`](config/nftables/pep-redirect.nft)
   pour la redirection réseau côté Debian. **Déployer d'abord en mode
   monitor** (log, pas de blocage) — jamais `closed` en premier (doctrine
   §5.3).
4. **NAC en parallèle** — [`config/freeradius/README.md`](config/freeradius/README.md) :
   802.1X/EAP-TLS réutilisant la même PKI que le handshake (§3), fail-closed
   forcé au niveau switch (pas seulement côté RADIUS), pas de VLAN assigné
   par RADIUS en v1.
5. **Durcissement hôte** — [`config/sysctl/99-tbp-hardening.conf`](config/sysctl/99-tbp-hardening.conf)
   sur chaque machine portant un composant TBP (broker, PEP, registre).
6. **Traducteur en dernier** (§13) — une fois le reste stable ; voir
   [`src/translator/README.md`](src/translator/README.md) pour le
   durcissement runtime attendu (non-root, cap-drop, seccomp — distinct de
   `dm-verity`, qui protège l'image au repos, pas le runtime).

À chaque étape, mesurer contre le budget de friction (§9.1) — voir
[`tests/p1_friction/README.md`](tests/p1_friction/README.md) pour les
seuils exacts. Le pilote échoue si la latence ou le taux d'arbitrage
dépassent ces seuils, même si tout fonctionne par ailleurs.

## Licence

Double licence, par sous-arbre :
- **`docs/` et `figs/`** : [CC BY 4.0](docs/LICENSE) — libre de partager
  et adapter avec attribution.
- **Tout le reste** (`config/`, `src/`, `policies/`, `lab/`, `tests/`,
  `.github/`) : [tous droits réservés](LICENSE) — fermé pour la phase de
  développement et de pilote actuelle ; une licence plus ouverte est
  prévue plus tard.

Voir [`CONTRIBUTING.md`](CONTRIBUTING.md) pour ce qui est ouvert aux
contributions dès maintenant (la documentation) et les règles à respecter
en modifiant la spec (normalisation terminologique, citations vérifiées,
changelog).

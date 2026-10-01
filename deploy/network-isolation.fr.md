# deploy/network-isolation.fr.md — prouver qu'aucune route de sortie n'existe hors TBP (issue #186)

_English version: [network-isolation.md](network-isolation.md)._

« Un agent ne peut pas contourner TBP pour atteindre l'extérieur » n'est **pas une propriété du code de
TBP**. C'est une propriété du **déploiement** : un VLAN dédié à la cellule, et des règles de pare-feu qui
forcent toute sortie à passer par le proxy bloquant du PEP (`src/pep/proxy.go`, #94). TBP ne prétend jamais
que c'est fermé — `config/nftables/pep-redirect.nft` est un squelette dont la vraie règle est commentée
(« ne pas déployer tel quel »). Une IA prendra la route hors TBP si elle existe : la garantie ne peut pas
reposer sur une configuration *supposée* correcte. Elle se teste, activement, à chaque déploiement :

```bash
deploy/verify_network_isolation.sh --allow 10.20.0.5:8081 --mode report   # calibration
deploy/verify_network_isolation.sh --allow 10.20.0.5:8081 --mode strict   # garde de déploiement
```

`--allow` est l'adresse du proxy bloquant du PEP (`TBP_PROXY_ADDR`), la **seule** destination que l'agent
peut atteindre.

## Ce qui est vérifié

1. **Contrôle positif.** La destination autorisée doit être *joignable* depuis le contexte de l'agent.
   Sans cela, « tout échoue » ne prouve rien (réseau tombé, mauvais contexte, proxy arrêté) — le script
   sort alors en `2`, jamais « conforme ».
2. **Sondes négatives.** Des connexions TCP vers des destinations arbitraires — IP internet (v4 et v6) et
   un nom DNS — doivent **toutes échouer**. Une connexion qui aboutit est une route de sortie : une
   violation.
3. **Règles réellement chargées.** Le noyau a la table nftables attendue avec au moins une règle *active*
   qui bloque ou redirige (une ligne commentée, comme dans le squelette, ne compte pas ; un fichier `.nft`
   sur le disque non plus).

## Où l'exécuter

Depuis **le contexte réseau de l'agent** — c'est lui qu'on éprouve :

| Situation | Option |
|---|---|
| L'agent tourne dans un espace de noms réseau | `--netns NOM` |
| L'agent est un conteneur ou une unit systemd | `--pid <pid principal>` |
| Les règles portent sur l'UID de l'agent (`meta skuid`) | `--as-user UTILISATEUR` |
| Vous êtes déjà dans le contexte de l'agent | aucune option |

Lire les règles du noyau demande `root` (ou `CAP_NET_ADMIN`) ; lancer le script en root et choisir le
contexte de l'agent avec les options ci-dessus, ou utiliser `--no-nft` en acceptant que le point 3 ne soit
pas vérifié.

## Modes — monitor avant closed (§5.3)

- `--mode report` (défaut) : affiche tout, sort `0` même avec des violations. Pour calibrer un nouveau
  déploiement dont les règles ne sont pas encore définitives.
- `--mode strict` : toute violation sort `1` ; des règles illisibles sortent `2` (il ne conclut pas sans
  avoir regardé). À brancher comme **garde de déploiement**, et à rejouer après tout changement des règles
  réseau.

Les codes de sortie sont ceux de `src/translator/audit_confinement.sh` : `0` conforme, `1` violation, `2`
erreur d'usage ou d'environnement.

## Ce que cela ne prouve pas

À dire franchement, pour que le rapport ne se lise pas comme une garantie :

- Seul le **TCP** est sondé. UDP, ICMP et les canaux cachés (tunnel DNS, un hôte autorisé qui relaie) ne
  le sont pas.
- Un échec de sonde n'est pas la preuve d'une règle (un hôte peut être simplement éteint) : d'où la liste
  de sondes variée et le contrôle positif obligatoire. Ajouter vos destinations avec `--probe HOTE:PORT`
  (y compris vos services internes que l'agent ne doit **pas** atteindre).
- Cela atteste l'état **au moment de l'exécution**. Le lancer à chaque déploiement et périodiquement ;
  l'audit du confinement du processus traducteur est un autre script (`src/translator/audit_confinement.sh`).
- Cela teste la route de l'agent vers l'extérieur, pas la bonne configuration du proxy du PEP : ce sont les
  tests propres du proxy (`src/pep`).

## Testé

`deploy/test_verify_network_isolation.sh` (lancé par `deploy/selftest/selftest.sh`, donc par la CI) attaque
le script avec de vrais écouteurs locaux — une route de sortie qui aboutit, un port refusé, une destination
autorisée injoignable, une règle commentée, une table absente, un `nft` illisible — et a été éprouvé par
mutation : retirer la sonde, le contrôle positif ou le filtre des commentaires fait passer un test au rouge.

# Plan de test AWS, après le passage Azure

_English version: [aws-test-plan.md](aws-test-plan.md). Fait partie de [deploy/dev-test](../README.fr.md). Le passage Azure qu'il suit : [2026-11-08-azure.fr.md](2026-11-08-azure.fr.md)._

> **Un plan, pas un résultat.** Rien de ce qui suit n'a été exécuté sur AWS. Les commandes des parties 5 et 8 ont été écrites
> d'après le code, pas exécutées par leur auteur ; si l'une ne fait pas ce qui est dit, c'est un constat, notez-le. Ce qui est
> marqué « à apprendre » est une question ouverte, pas une attente : ne le lisez pas comme une affirmation.

Le but : le même test que sur Azure (pour comparer les chiffres), puis les mesures qu'Azure a laissées ouvertes, avec les
chronométrages notés. Les machines : [aws.fr.md](../cloud/aws.fr.md) (3 × `m6i.large`, 2 CPU et 8 Go, comme les
`Standard_D2s_v5` du passage Azure ; une taille « burstable » comme `t3` rendrait la comparaison plus difficile : son CPU
dépend de crédits).

Le lieu d'exécution est dans la première colonne : **PC** (votre ordinateur), **M1**, **M2**, **M3** (les machines, dans
`~/TBP-NETWORK`). Notez chaque résultat dans le tableau final au fur et à mesure.

## 1. Déployer, avec les temps

| Où | Commande | À noter |
|---|---|---|
| PC | les étapes 1 à 5 de [aws.fr.md](../cloud/aws.fr.md), avec `time` devant la ligne `aws cloudformation deploy` | la durée de la pile ; la région ; la taille |
| M1 | `init` comme dans [README.fr.md](../cloud/README.fr.md), avec `--env "aws, m6i.large, <région>"`, avec `time` devant | la durée d'`init` sur une machine **froide** (rien de téléchargé avant) |
| M2, M3 | leur `init`, avec `time` | les durées |
| M1, M2 | `scripts/devtest/site.sh m1 up`, `… m2 up`, avec `time` | les durées |

`site.sh m1 report` reprend les durées d'`init` et d'`up` (et le commit, le noyau, les CPU) : gardez les trois rapports.

## 2. Les étapes 1 à 14 de site.fr.md

Faites le tableau de [site.fr.md](../site.fr.md#quoi-tester--est-ce-que-ça-marche-) tel quel, sur la console, et notez dans le tableau
des résultats si chaque étape donne la même réponse que sur Azure (la colonne Azure du [rapport](2026-11-08-azure.fr.md)). Le paragraphe
sur les jetons et les approbations donne le rythme : un jeton vit 30 à 60 secondes.

## 3. La décision de la cellule et le verdict de l'application

Sur M3 :

```bash
cd ~/TBP-NETWORK && scripts/devtest/site.sh m3 report
```

Comparez avec le rapport Azure : décision de la cellule pour une demande refusée faute de plan (Azure : p50 553,5 ms, écart
de 3 ms), `/healthz` de l'application, le réseau entre M3 et la cellule. Sur M2, `site.sh m2 report` : le verdict de `pepd` sur
un jeton mal formé (Azure : 7,7 ms). Pour un jeton **valide** (Azure : environ 260 ms, contre environ 7 ms pour un refus),
lisez la console après l'étape 3 puis après l'étape 11, cinq fois si possible (approuver, `act`, recommencer).

À apprendre : les 550 ms de la cellule et les 260 ms d'un verdict valide se retrouvent-ils sur AWS avec les mêmes valeurs ?
Si oui, ils ne viennent pas du cloud.

## 4. OPA seul

Sur M1 :

```bash
cd ~/TBP-NETWORK && export PATH=/usr/local/go/bin:$PATH && go run ./tests/opa_latency -transport unix -concurrency 1,4 -out ~/opa-latency.json
```

Gardez la fin de la sortie (Azure : 0 `opa-timeout` sur 4 000 requêtes d'un flux ; 3,3 % à 4 simultanées).

## 5. Décisions en parallèle

Sur M3, un sujet (`agent-i`), 48 refus par tour, comme sur Azure :

```bash
cd ~/TBP-NETWORK
for P in 1 2 3 4 16; do echo "== en même temps : $P"; time (seq 48 | xargs -P $P -I{} scripts/devtest/site.sh m3 act agent-i read doc-1 2>&1 | grep -o '"reason":"[a-z-]*"' | sort | uniq -c); done
```

Azure : 36,3 s, 20,5 s, 12,3 s, 9,8 s, 8,3 s, et `opa-overloaded` 0, 0, 1, 13, 42 sur 48. Notez le temps et le décompte de
chaque raison pour chaque ligne. Sur M1, `grep -c opa-timeout ~/tbp-site-m1/log/brokerd.log` avant et après la série.

**Facultatif, avec les places de la cellule portées à 4** (sauvegardez le fichier d'abord ; cela redémarre la cellule, donc
refaites les étapes qui demandent un état neuf) :

```bash
# M1
cd ~/TBP-NETWORK && scripts/devtest/site.sh m1 down && cp ~/tbp-site-m1/m1.env ~/m1.env.bak && echo 'TBP_OPA_MAX_INFLIGHT=4' >> ~/tbp-site-m1/m1.env && scripts/devtest/site.sh m1 up
# M3 : la même boucle avec  for P in 4 16
# M1, pour restaurer
scripts/devtest/site.sh m1 down && cp ~/m1.env.bak ~/tbp-site-m1/m1.env && scripts/devtest/site.sh m1 up && grep -c MAX_INFLIGHT ~/tbp-site-m1/m1.env
```

La dernière commande doit afficher `0`.

## 6. L'écriture qui suit un verdict (facultatif, M2 et M3)

`pepd` répond quand sa feuille d'audit est *acceptée*, puis le log signé rattrape en arrière-plan ; une coupure dans la
fenêtre d'une seconde refuse. Cette partie demande ce qu'un arrêt brutal laisse derrière lui. À apprendre : le journal
contient-il parfois un enregistrement que le log n'a pas, après un `kill -9` ?

Sur **M2**, lancez ceci et laissez-le attendre (il tue `pepd` dès qu'un enregistrement de plus est écrit dans son journal) :

```bash
cd ~/tbp-site-m2 && n=$(wc -l < audit/pepd-records.jsonl) && while [ "$(wc -l < audit/pepd-records.jsonl)" -le "$n" ]; do :; done; kill -9 "$(cat run/pepd.pid)"; echo killed
```

Sur **M1**, approuvez un plan (`site.sh m1 sign agent-i read doc-5`), sur **M3** lancez la ligne `act` qu'il affiche. Puis sur M2 :

```bash
cd ~/TBP-NETWORK && scripts/devtest/site.sh m2 up        # il revient « refused » : rouvrez-le comme aux étapes 9-10 pour continuer
~/tbp-site-m2/bin/tbp-audit verify -records ~/tbp-site-m2/audit/pepd-records.jsonl -key ~/tbp-site-m2/pepd-audit.key \
  -log ~/tbp-site-m2/registry/pepd -vkey-file ~/tbp-site-m2/registry/pepd/cell_log.vkey; echo "sortie $?"
```

Notez toute la sortie. Sortie 0 : chaque enregistrement a sa feuille et chaque feuille son enregistrement ; 1 : un
enregistrement sans feuille (ou l'inverse) est nommé. L'un et l'autre sont un résultat. Recommencez deux ou trois fois : la
fenêtre est courte.

## 7. Les fichiers (les attaques de site.fr.md)

Le tableau « Sur M2 — quelqu'un qui peut écrire les fichiers du serveur » et la ligne sur M1 de [site.fr.md](../site.fr.md#lattaquer) :
`site.sh m2 down`, faites la modification, `m2 up`, notez le message, restaurez le fichier. Le passage Azure ne les a pas faites.

## 8. Beaucoup de requêtes invalides (en dernier : cela peut laisser `pepd` coupé)

Un jeton vide est refusé par l'application. Un jeton **non vide mais invalide** atteint `pepd`, qui enregistre un verdict.
Cela demande ce qu'un déluge fait au journal et au log de `pepd`. Faites-le en dernier, et comptez redémarrer `pepd`.

Sur M3 :

```bash
URL=$(cat ~/tbp-site-m3/state/app-url)
time (seq 2000 | xargs -P 8 -I{} curl -s -o /dev/null -w '%{http_code}\n' -H 'X-TBP-Token: AAAA' "$URL/read/doc-1" | sort | uniq -c)
```

Sur M2, juste après :

```bash
cd ~/tbp-site-m2 && grep -c ALARME log/pepd.log; grep ALARME log/pepd.log | tail -3
wc -l audit/pepd-records.jsonl; du -sh audit registry
~/TBP-NETWORK/scripts/devtest/site.sh m2 status
```

Puis, depuis M1 et M3, obtenez un jeton **valide** (comme aux étapes 2–3) et présentez-le. Notez s'il est exécuté, refusé, et
avec quelle raison. À apprendre : un déluge de requêtes invalides fait-il échouer les valides qui suivent (la coupure
`leaf-write-failed`) ? Ce serait un déni de service inhérent à « pas de feuille, pas de réponse » ; savoir si c'est
acceptable est une décision pour les mainteneurs, pas pour ce plan.

## 9. Tout supprimer

`aws cloudformation delete-stack --stack-name tbp-devtest` ([aws.fr.md](../cloud/aws.fr.md#7-mettre-en-pause-reprendre-supprimer)), vos copies
des paquets, et les preuves sur votre ordinateur. Vérifiez dans la console (EC2, Elastic IPs) qu'il ne reste rien qui coûte.

## Résultats

| # | Mesure | Azure (2026-11-08) | AWS |
|---|---|---|---|
| 1 | création de la pile | (modèle exécuté une fois) | |
| 1 | `init` M1 / M2 / M3, à froid | 19 s / 1 s / 0 s (cache Go chaud) | |
| 1 | `up` M1 / M2 | 3 s / 3 s | |
| 2 | étapes 1–14 : mêmes réponses ? | voir le rapport | |
| 3 | décision de la cellule, refus, p50 / p95 | 553,5 / 555,1 ms | |
| 3 | verdict de `pepd`, jeton mal formé, p50 | 7,7 ms | |
| 3 | verdict de `pepd`, jeton valide | 255–272 ms | |
| 3 | classe I / classe W acceptées par la cellule | environ 780 ms / 1,04 s | |
| 4 | OPA seul : `opa-timeout` sur 4 000 / à 4 simultanées | 0 / 3,3 % | |
| 5 | 48 refus à 1, 2, 3, 4, 16 simultanées : temps | 36,3 ; 20,5 ; 12,3 ; 9,8 ; 8,3 s | |
| 5 | `opa-overloaded` | 0, 0, 1, 13, 42 | |
| 5 | avec 4 places, à 4 et 16 | 0, 32 | |
| 5 | `opa-timeout` dans `brokerd.log` | 1 dans les 67 premières | |
| 6 | `tbp-audit verify` après `kill -9` | non fait | |
| 7 | attaques de fichiers | non fait | |
| 8 | déluge de 2 000 requêtes invalides : durée, nombre d'`ALARME`, requête valide ensuite | non fait | |

Collez les trois `report` et ce tableau dans une issue **Dev-test feedback** (le titre commence par `[dev-test]`). Tout ce qui
est exploitable va en privé, comme le dit [SECURITY.md](../../../SECURITY.md).

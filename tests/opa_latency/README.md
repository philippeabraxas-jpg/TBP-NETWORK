# opa_latency — la latence réelle d'OPA contre le disjoncteur de 5 ms

Le budget §9.1 (« latence tier 1 ajoutée < 5 ms ») est tenu par `pep.EvalTimeout` : au-delà de 5 ms, l'appel OPA
est un `opa-timeout` — **deny fail-closed**, alarme T14, et, après `TripAfter` fautes consécutives (3 par défaut,
`TBP_OPA_TRIP_AFTER`), **verrou du PEP**. Le harnais de friction (`tests/p1_friction`) mesure le PEP **seul**, OPA nil :
il ne dit rien de ce que coûte OPA. Cet outil le mesure avec le **vrai OPA**, la **vraie politique**
(`policies/rego/*.rego`) et le **vrai client** (`pep.OPAClient`, budget par défaut), en **TCP loopback** et en
**socket Unix + SO_PEERCRED** (le transport nominal, §92.A3).

```sh
go run ./tests/opa_latency                                  # les deux transports, tous les niveaux
go run ./tests/opa_latency -transport unix -concurrency 1,4 -out rapport.json
taskset -c 2,3 go run ./tests/opa_latency -opa-cpus 0,1     # OPA et le client sur des cœurs DISTINCTS
```

Trois mesures, par transport :

| Mesure | Ce qu'elle dit |
|---|---|
| **À froid** | N démarrages d'OPA ; pour chacun, la **1re requête** du client réel (connexion neuve, caches froids) puis la 2e |
| **Après inactivité** | OPA chaud, puis une requête après une pause (`-idle-gap`) |
| **Charge** | concurrence croissante : latence **vraie** (passe brute, le client n'abandonne pas à 5 ms) **et** verdicts du client réel au budget (combien d'`opa-timeout`) |

L'outil **ne juge pas** : il rend des chiffres (stdout + `-out` JSON). Ce n'est pas un contrôle de CI (il exige le
binaire `opa` ; son test de bout en bout est sauté sans lui).

## Résultats — une photographie datée (2026-10-02)

**Machine** : VM de développement, 4 CPU, `linux/amd64`, OPA 1.20.2, politique `policies/rego` (exemple d'action +
3 paquets de gardes), requête `read` de classe W. **À lire comme un ordre de grandeur sur CETTE machine, pas comme
un résultat de production** : le matériel du pilote (§15) n'est pas celui-ci. Les rapports bruts sont dans
`results/`.

### 1. À froid : la première requête paie ~2× la deuxième

| Config | 1re requête p50 | 1re requête max | 1re > 5 ms | 2e requête p50 | 2e > 5 ms |
|---|---|---|---|---|---|
| TCP, cœurs partagés (20 essais) | 3,1 ms | 6,3 ms | 2/20 (10 %) | 1,5 ms | 0/20 |
| Unix, cœurs partagés (20 essais) | 2,6 ms | 5,5 ms | 1/20 (5 %) | 1,3 ms | 0/20 |
| TCP, OPA sur 2 cœurs dédiés (20) | 2,6 ms | 5,8 ms | 1/20 (5 %) | 1,5 ms | 1/20 |
| Unix, OPA sur 2 cœurs dédiés (20) | 2,4 ms | 5,6 ms | 2/20 (10 %) | 1,7 ms | 0/20 |
| Unix, OPA sur 1 cœur (10) | 2,9 ms | 5,0 ms | 1/10 (10 %) | 1,3 ms | 0/10 |

Un premier essai ad hoc (client Go brut, sans le client réel) avait donné 5/15 > 5 ms. **La fourchette honnête est
« 5 à 33 % des démarrages à froid dépassent 5 ms sur la première requête »**, selon la charge de la machine à cet
instant. Conséquence : le **premier** verdict d'un PEP qui vient de démarrer peut être un `opa-timeout` sans qu'OPA
soit malade — c'est ce que le selftest masquait déjà par un échauffement (`warmOPA`, deux occurrences vues).
Après 3-5 s d'inactivité, aucune dégradation mesurée (p50 1,6-1,9 ms, 0 dépassement).

### 2. Un flux seul tient largement le budget

Concurrence 1, OPA chaud : p50 ≈ 0,9-1,1 ms, p99 ≈ 2,7-3,3 ms, p99,9 ≈ 4-7 ms ; **0,1-0,3 % de dépassements**
(`opa-timeout` du client réel : 0,0-0,2 %) — des pauses isolées (GC, ordonnancement), pas une saturation.

### 3. La concurrence fait s'effondrer le budget

Part des décisions du **client réel** rendues en `opa-timeout` (4 000 requêtes par case) :

| Concurrence | TCP, cœurs partagés | Unix, cœurs partagés | Unix, OPA sur 2 cœurs dédiés | Unix, OPA sur 1 cœur |
|---|---|---|---|---|
| 1 | 0,1 % | 0,1 % | 0,1 % | 0,0 % |
| 4 | 1,1 % | 1,4 % | 5,4 % | 35 % |
| 8 | 14,0 % | 14,5 % | 53 % | — |
| 16 | 82 % | 84 % | 99,3 % | — |

Latence vraie à concurrence 8 (OPA sur 2 cœurs, Unix) : p50 2,6 ms, p90 7,1 ms, p99 25 ms ; à 16 : p99 73 ms.

**Lecture.** Un OPA coûte ~1 ms par évaluation (HTTP + JSON + règles) ; il sature autour de **2-3 requêtes
concurrentes par cœur**. Au-delà, deux effets s'ajoutent : (1) la file d'attente d'OPA entre dans le budget de
5 ms ; (2) le client qui abandonne à 5 ms **n'annule pas le travail d'OPA** — la requête abandonnée est quand même
évaluée, ce qui entretient la saturation (à concurrence 16 sur 2 cœurs : 99,7 % de timeouts, l'effondrement). Avec
`TripAfter = 3`, ce sont les timeouts **consécutifs** qui verrouillent le PEP : à 300 req/s et des timeouts
supposés indépendants, trois d'affilée surviennent environ toutes les heures à 1 % de timeouts, environ toutes les
30 s à 5 % — et les timeouts réels sont corrélés (rafales, file d'attente d'OPA), donc pires que cette estimation.

### Ce que ces chiffres NE disent PAS
- Le matériel du pilote : sur des cœurs plus rapides le point de saturation monte, il ne disparaît pas.
- Un bundle **signé** : la vérification de signature coûte au chargement, pas à l'évaluation (non mesuré ici).
- Le coût d'une politique plus riche que l'exemple : le chiffre dépend directement des règles (§10.5).
- L'effet du reste du chemin (token, registre) : c'est le rôle de `tests/p1_friction`.

## Leviers (non appliqués ici — décisions d'arbitrage)
1. **Échauffement au démarrage** (avant de servir) : quelques évaluations brutes (sans feuille) pour sortir du froid.
2. **Limiter la concurrence vers OPA** dans le client (sémaphore borné) : la file attend côté PEP, hors d'OPA, et un
   dépassement devient un refus immédiat et explicite plutôt qu'un effondrement.
3. **Dimensionner OPA** : ≥ 1 cœur par ~2-3 décisions concurrentes visées ; ou plusieurs instances.
4. **Revoir le budget ou `TripAfter`** : une décision de spec (§9.1), pas de code.

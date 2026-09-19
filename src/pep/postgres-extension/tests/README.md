# Tests T17 — protocole étendu, ORM, pooler (issue #20)

Suite **pytest** dédiée à l'extension `tbp_pg` (T16), centrée sur ce qu'un
test naïf à hook unique ne verrait pas : **prepared statements du protocole
étendu, ORM réel, pooler de connexions**. Doctrine (cf.
`tests/p2_redteam/README.md`) : **chaque blocage est prouvé par une feuille
registre vérifiable** (ligne `TBP_LEAF` JSON parsée : phase, raison, sceau) —
un test qui « passe » sans trace n'a rien prouvé. Ces scénarios alimentent la
campagne red-team P2 (T28, §13).

## Fichiers

| Fichier | Rôle |
|---|---|
| `conftest.py` | Instance PG 15 jetable (initdb + preload), helpers feuilles, cycle monitor → autorisation → closed, recette de provisionnement pilote. |
| `test_prepare_execute.py` | Scénarios 1 et 2 de l'issue : PREPARE/EXECUTE à valeur liée hostile ; fonction volatile interceptée au parse **avec preuve d'absence d'effet de bord** ; wrapper IMMUTABLE enrobant du volatile ; interpolation psycopg2 (une valeur = un sceau) ; feuilles hash-only (§6.2). |
| `test_orm_sqlalchemy.py` | Scénario 3 : SQLAlchemy/psycopg2 — provisionnement des requêtes maison du pilote, requête déviante bloquée + feuille. |
| `test_pooler_pgbouncer.py` | Derrière pgbouncer : sceau présenté en mode session (OK) et en mode transaction (ne traverse PAS — démonstration orchestrée par `pg_backend_pid`) ; cache D7 partagé entre backends ; SQLAlchemy à travers le pooler. |
| `docker-compose.yml`, `Dockerfile.tests` | Reproduction en conteneur (CI). |
| `ci.github-workflow.yml` | Workflow prêt à copier dans `.github/workflows/` (token sans scope `workflow` à ce jour). |
| `pgbouncer/` | Exemple de configuration de déploiement du pooler. |

## Lancement local (sans docker)

Prérequis : PostgreSQL 15 + `postgresql-server-dev-15` (D3, épinglé),
extension compilée/installée (`make install`), pgbouncer, et
`pip install pytest sqlalchemy psycopg2-binary`.

```sh
TBP_PG_CONFIG=/chemin/pg_config \
TBP_PGBOUNCER=$(command -v pgbouncer) \
python3 -m pytest tests/ -v
```

`TBP_TEST_PORT` (défaut 55444) fixe le port de l'instance jetable ; les
poolers prennent +10/+11. Sans `TBP_PGBOUNCER`, les scénarios pooler sont
sautés **avec un message explicite** (jamais silencieusement).

## En conteneur (CI)

```sh
docker compose -f tests/docker-compose.yml up --build --exit-code-from tests
```

Un seul conteneur, par doctrine : la bascule monitor → closed passe par
`ALTER SYSTEM` + `pg_ctl reload` (`pg_reload_conf()` serait elle-même
refusée par le hook 1 — fonction volatile — dès `tbp.enforce=on` ; la
politique ne doit pas se mordre la queue), donc le harnais garde le contrôle
local du postmaster.

## Recette de provisionnement pilote/ORM (limite T16 approfondie)

Dès la connexion, le pilote émet ses sondes (SQLAlchemy/psycopg2 :
`version()` et `current_schema()` — STABLE, déni de fonction du hook 1 ;
détection hstore → `pg_catalog.pg_type` **et** `pg_catalog.pg_namespace` —
déni de table). En mode closed, elles sont soumises à la même politique
(fail-closed voulu, §1). La recette — implémentée par
`Pg.provision_driver(exercise)` et testée bout en bout :

1. **monitor** (§5.3) : jouer le flux complet du pilote (connexion, sondes,
   requêtes métier) — rien n'est bloqué, tout est tracé ;
2. **récolte** : tables/fonctions des feuilles `would_deny` structurelles →
   listes blanches ; sceaux des feuilles `seal-unauthorized` →
   `tbp_authorize` (cache D7) ;
3. **itérer** jusqu'à convergence : le walker du hook 1 s'arrête au premier
   refus, une passe ne révèle qu'une entrée manquante (2 passes suffisent
   pour SQLAlchemy : `pg_type` puis `pg_namespace`) ;
4. **closed** : `tbp.enforce=on` — la connexion et le métier passent, le
   déviant est bloqué avec feuille.

## Pooler : ce que les tests démontrent (D9)

- Le **sceau présenté** (`tbp_present_seal`, object-capability §4.4(2)) est
  posé **par backend PostgreSQL**, usage unique. `pool_mode=session` :
  affinité backend garantie, la présentation fonctionne.
  `pool_mode=transaction` : chaque transaction peut toucher un autre backend
  — le sceau présenté ne traverse PAS (fail-closed + feuille), démontré en
  monopolisant les backends identifiés par `pg_backend_pid()`.
- Le **cache de décision D7** (mémoire partagée de l'instance) est le canal
  légitime derrière un pooler : un sceau autorisé une fois est servi par
  tous les backends (prouvé sur 3 backends distincts).
- Conséquence déploiement : clients présentant des sceaux →
  `pool_mode=session` ; clients à sceaux autorisés → tout mode.

## Notes de déploiement (journalisation, §6.2)

- Les **feuilles** sont hash-only : jamais de valeur liée en clair (testé).
  En revanche PostgreSQL lui-même échoûte le texte des requêtes en erreur
  (`STATEMENT:` via `log_min_error_statement`) : si les valeurs liées sont
  sensibles, régler `log_min_error_statement` en conséquence — ce canal est
  hors feuille mais visible au registre.
- `pg_backend_pid()`, `version()`, `current_schema()` sont STABLE : comme
  toute fonction non immuable, elles exigent `tbp.allowed_functions` en mode
  closed (le provisionnement les récolte).
- Les corps des fonctions SQL sont analysés — donc gouvernés — à leur
  première compilation (hook 1) et exécutés sous sceau (hook 2) : un
  wrapper `IMMUTABLE` enrobant une fonction volatile est refusé dès le
  `CREATE FUNCTION` sous enforce. En monitor, le même `CREATE` laisse une
  feuille `would_deny` — la campagne P2 (T28) exploitera cette piste.

## Chaîne de décisions

- **D8** — pytest + psycopg2, zéro dépendance docker pour la boucle locale ;
  le compose ne sert qu'à la CI/reproduction.
- **D9** — derrière un pooler, autorisation par le cache partagé D7 ; le
  sceau présenté exige l'affinité session. Démontré, pas contourné.

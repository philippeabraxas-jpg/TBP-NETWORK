# PostgreSQL PEP extension (spec §4.4)

In-process mitigation for aliasing (order → effect drift) inside
PostgreSQL: the spec (§4.4) blocks at `post_parse_analyze_hook` rather
than `ExecutorStart_hook` alone, because `ExecutorStart` is post-planning
— a side-effecting function can already have been evaluated by the time
that hook fires.

**`post_parse_analyze` alone is not enough either, for a different
reason.** It fires once, at parse time. For an extended-query-protocol
prepared statement (`PREPARE ...; EXECUTE ... ($1, $2)`) — exactly what
connection poolers and ORMs (SQLAlchemy, Prisma, etc.) do by default to
reuse parse/plan work — the parse tree is built once, with placeholders,
and validated once. Every subsequent `EXECUTE` with concrete parameter
values skips `post_parse_analyze` entirely. A rule validated against
`$1 = 'safe_value'` at prepare time proves nothing about the actual value
bound at execute time.

## Required: hook both, for different purposes

- **`post_parse_analyze_hook`** — structural validation (which tables,
  which operation) against the parse tree, as already specified in §4.4.
- **`ExecutorStart_hook`** — validate a **sealed hash of the finalized
  plan, including bound parameter values** (not placeholders),
  immediately before execution. This closes the prepared-statement/ORM
  gap above.

This does **not** reopen the risk the spec already ruled `ExecutorStart`
out for. That risk was about relying on `ExecutorStart` *alone* to catch
effects already evaluated during planning. Hooking it *in addition to*
`post_parse_analyze`, solely to check bound parameters against an
already-sealed plan hash, doesn't reintroduce it — the structural
decision still happens at parse time; `ExecutorStart` only checks that
the values actually being executed match what was authorized.

## Implemented (T16)

### Decisions

- **D3 — C natif + PGXS, PostgreSQL 15 épinglé.** Les signatures des
  hooks (`post_parse_analyze_hook(ParseState *, Query *, JumbleState *)`,
  `ExecutorStart_hook(QueryDesc *, int)`) sont celles de PG 15 ; changer
  de majeure impose une revue (les signatures bougent).
- **D7 — sceau calculé par l'extension elle-même + cache de décision
  borné en mémoire partagée.** Pas de broker ni d'OPA sur le chemin
  synchrone : le sceau est un SHA-256 calculé in-process (OpenSSL
  `EVP_Q_digest`), la décision tient dans une table de hachage shm
  (`tbp.cache_entries`, défaut 4096) protégée par LWLock. **Borné, jamais
  d'éviction (§4.3)** : la saturation ferme (refus + alarme `TBP: ALARME`
  dans le journal). Seule la gouvernance peuple le cache
  (`tbp_authorize`, restreinte au superuser et à `tbp.authorizer_role`).

### Hook 1 — `post_parse_analyze` (structurel, au parse)

- Liste blanche de commandes (`tbp.allowed_commands` :
  SELECT/INSERT/UPDATE/DELETE/MERGE — vide = tout refusé, fail-closed §1).
- Liste blanche de tables (`tbp.allowed_tables`, noms canoniques
  `schema.table` — vide = tout refusé).
- **Deni des fonctions non immutables** (VOLATILE/STABLE) : le
  const-fold du planificateur peut les *évaluer* dès la planification —
  un effet de bord partirait avant tout hook d'exécution. Les fonctions
  immutables passent, les `tbp_*` passent, le reste va dans
  `tbp.allowed_functions`.
- Le walker descend dans les CTE (`cteList`) et les sous-requêtes du
  FROM (`RTE_SUBQUERY`) — pas de contournement par imbrication.
- Les commandes utilitaires (DDL, `ALTER SYSTEM`, `SHOW`…) ne sont pas
  soumises à ce hook (périmètre = DML ; le DDL reste sous contrôle
  PostgreSQL classique).

### Hook 2 — `ExecutorStart` (sceau de plan, juste avant exécution)

Sceau = SHA-256 sur :

1. `nodeToString(PlannedStmt)` **avec `rtable = NIL`** (les
   `RangeTblEntry` ne sont pas sérialisables par `nodeToString`) ;
2. la liste canonique `schema.table` des relations du plan (qui reste
   ainsi liée au sceau) ;
3. les **valeurs des paramètres liés** (type + valeur textuelle, `NULL`
   distingué) — ce qui ferme le trou PREPARE/EXECUTE.

Décision : cache de décision (D7) → sinon sceau présenté
(`tbp_present_seal`, object-capability §4.4(2), **usage unique**, par
backend, consommé match ou non, et qui **n'élargit pas le cache** —
sinon tout backend de l'instance hériterait de la capacité) → sinon
refus `seal-unauthorized`. Les requêtes ne touchant aucune relation ne
sont pas scellées (le hook 1 les couvre déjà).

### Mode monitor d'abord (§5.3)

`tbp.enforce` = **off par défaut** : rien n'est bloqué, chaque décision
laisse une feuille `would_deny: true`. On récolte les sceaux depuis le
journal, on les autorise (`tbp_authorize`), puis on bascule `enforce =
on`. Chaque porte ouverte naît avec son compteur — et chaque décision
avec sa feuille (§4.1).

### Feuilles (§4.1, §6.2)

Une ligne `TBP_LEAF {…}` dans le journal PostgreSQL, **avant** tout
refus, pour chaque décision des deux hooks :

```json
{"v":1,"phase":"parse|exec","cell":"…","allow":true,"would_deny":false,
 "reason":"ok|structural-deny-command|structural-deny-table|structural-deny-function|seal-unauthorized|seal-mismatch|cache-saturated",
 "cmd":"SELECT|INSERT|UPDATE|DELETE|MERGE|OTHER","tables":["public.docs"],
 "seal":"<64 hex>","detail":"…","elapsed_us":21}
```

Hash-only (§6.2) : jamais de valeur de paramètre en clair dans la
feuille — seulement le sceau.

### GUC

| GUC | Défaut | Rôle |
|---|---|---|
| `tbp.enforce` | `off` | off = monitor (§5.3) ; on = closed. `PGC_SUSET`. |
| `tbp.allowed_commands` | `""` | Commandes DML autorisées (vide = fail-closed). |
| `tbp.allowed_tables` | `""` | Tables autorisées, `schema.table`. |
| `tbp.allowed_functions` | `""` | Fonctions non immutables explicitement admises. |
| `tbp.cell_id` | `""` | Identité de cellule portée par les feuilles. |
| `tbp.authorizer_role` | `""` | Rôle habilité `tbp_authorize`/`tbp_forget_all`. |
| `tbp.cache_entries` | `4096` | Capacité du cache de décision (postmaster, §4.3). |

### API SQL

| Fonction | Rôle |
|---|---|
| `tbp_present_seal(text) → bool` | Présente le sceau du jeton (§4.4(2)) pour la prochaine exécution de CE backend — usage unique. Tout rôle. |
| `tbp_authorize(text) → bool` | Inscrit un sceau au cache de décision (gouvernance : superuser ou `tbp.authorizer_role`). |
| `tbp_cache_count() → bigint` | Occupation du cache de décision. |
| `tbp_forget_all() → void` | Vide le cache (gouvernance). |
| `tbp_sha256(text) → text` | SHA-256 hex (outillage hors ligne, vecteurs FIPS). |

### Latence (§9.1)

Mesuré sur les feuilles `exec` du banc d'essai (200 `EXECUTE` en
boucle, instance locale) : **moyenne ≈ 20 µs, max ≈ 300 µs** par
décision — très en deçà du budget tier 1 (< 2–5 ms). La validation
synchrone tient ; le cache D7 sert de mécanisme d'autorisation, pas de
correctif de latence.

### Limites connues

- **`shared_preload_libraries = 'tbp_pg'` requis** (cache shm + hooks au
  démarrage). Sans preload, l'extension se charge mais le cache est
  indisponible (seul `tbp_present_seal` autorise) — journalisé.
- **`plan_cache_mode`** : PostgreSQL utilise des plans *custom* pour les
  ~5 premières exécutions d'un prepared statement puis bascule au plan
  *générique*. Deux plans distincts = deux sceaux distincts : les deux
  doivent être autorisés. C'est voulu — le sceau lie le plan exact, pas
  une intention.
- Le sceau présenté est par backend (pooler : chaque connexion présente
  le sien, cf. T17 pour les tests pooler).
- **Requêtes maison des pilotes/ORM** : dès la connexion, le pilote émet
  ses propres sondes (SQLAlchemy/psycopg2 : détection hstore →
  `pg_catalog.pg_type`). En mode closed elles sont soumises à la même
  politique — fail-closed voulu — et le provisionnement des listes
  blanches doit en tenir compte (sinon la connexion elle-même est
  refusée). Approfondi en T17.
- DDL/commandes utilitaires hors périmètre du hook 1.
- PG 15 épinglé (D3) — toute montée de majeure = revue des signatures.

## Tests

```sh
make PG_CONFIG=/chemin/pg_config            # with_llvm=no si clang absent
make PG_CONFIG=/chemin/pg_config install
PG_CONFIG=/chemin/pg_config sh test/run_tests.sh
```

`test/run_tests.sh` crée une instance jetable et joue les critères
d'acceptation : PREPARE/EXECUTE à valeur hostile bloqué, fonction
volatile bloquée au parse, sceau présenté à usage unique, CTE/sous-
requêtes, fail-closed partout, latence < budget. `test/orm_sqlalchemy.py`
rejoue le scénario via l'ORM SQLAlchemy (protocole étendu, prepared
statements implicites).

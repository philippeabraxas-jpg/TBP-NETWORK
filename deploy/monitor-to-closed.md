# deploy/monitor-to-closed.md — bascule gouvernée §5.3 (T35, issue #61)

Le mode **closed** ne s'installe pas : il se **mérite**. La posture de
démarrage est monitor partout (§5.3) ; la bascule exige les points de
mesure §9.1 installés et alimentés (D100), une fenêtre d'observation, et
un **quorum** — un opérateur seul ne peut pas fermer le réseau
(démontré par la phase mono du selftest : 1 signataire → 403, quorum →
200).

> MAB : voir [checklists/routeur.md](checklists/routeur.md) — le MAB est
> une affaire NAC/switch (machine routeur), pas de posture PEP. La
> doctrine partagée est « jamais silencieux » : ni un équipement MAB non
> journalisé, ni une bascule non tracée (feuille `KindTelemetry`, §4.1).

#### Étape 1 — Vérifier que la mesure précède la posture (D100)

**Prérequis vérifiable** : toutes les machines en monitor (cellule.md,
serveur.md) depuis la fenêtre d'observation convenue ; le superviseur
collecte les feuilles des cellules (superviseur.md étape 4).

**Commande** :

```bash
# Référence exécutable des points de mesure §9.1 (T27) :
go test ./tests/p1_friction/ -count=1
# Sur chaque PEP :
curl -s http://127.0.0.1:8443/v1/mode    # attendu : {"mode":"monitor"}
```

**Critère de succès observable** : les points de mesure §9.1 (forwarded,
would-deny, denied, latences p50/p99) sont installés ET alimentés ; le
registre de chaque cellule montre des feuilles `KindDecision` en monitor
(une évaluation allow = verdict + passeport, §4.1-bis — mesuré par le
selftest).

**En cas d'échec : STOP** — sans mesure alimentée, aucune demande de
closed ; « on verra après » est exactement ce que §5.3 interdit.

#### Étape 2 — Lire la fenêtre d'observation

**Prérequis vérifiable** : étape 1 verte.

**Commande** :

```bash
# Pour chaque cellule : compter les would-deny de la fenêtre (verdicts
# deny journalisés en monitor). Chaque would-deny est un flux qui AURAIT
# été bloqué en closed — chacun doit être expliqué ou accepté
# explicitement avant la bascule.
go run ./deploy/selftest -phase mono   # montre would-deny sur témoin write
```

**Critère de succès observable** : liste des would-deny de la fenêtre,
chacun classé (légitime / à corriger / règle à adapter dans les policies
propres du pilote, §14).

**En cas d'échec : STOP** — un would-deny inexpliqué bloque la bascule ;
fermer sans l'expliquer, c'est aveugler le réseau.

#### Étape 3 — Demander la bascule au quorum (par PEP)

**Prérequis vérifiable** : étapes 1-2 vertes ; les signataires sont
prévenus et joignables ; la fenêtre de rollback (étape 4) est décidée.

**Commande** :

```bash
# Le vérificateur de quorum actuel compte les signataires (TBP_QUORUM_MIN,
# défaut 2) — la crypto de quorum est une phase ultérieure, la couture est
# en place. 1 signataire DOIT échouer :
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8443/v1/mode \
  -H 'Content-Type: application/json' -d '{"mode":"closed","signers":["op-1"]}'
# attendu : 403. Puis, quorum réuni :
curl -s -X POST http://127.0.0.1:8443/v1/mode \
  -H 'Content-Type: application/json' \
  -d '{"mode":"closed","signers":["op-1","op-2"]}'
curl -s http://127.0.0.1:8443/v1/mode
```

**Critère de succès observable** : 403 sans quorum, 200 avec ;
`GET /v1/mode` rend `{"mode":"closed"}` ; la bascule laisse une feuille
`KindTelemetry` dans le registre de la cellule (comptée par le selftest).

**En cas d'échec : STOP** — un 200 sans quorum = vérificateur cassé :
rester en monitor et corriger ; un 403 avec quorum = signataires
insuffisants, refaire la demande proprement.

#### Étape 4 — Observer en closed, rollback prêt

**Prérequis vérifiable** : étape 3 verte.

**Commande** :

```bash
# En closed, un veto OPA bloque : forwarded=false (démontré par la phase
# mono du selftest). Surveiller denied et les alarmes fail-closed (T14).
# Rollback = bascule gouvernée inverse :
curl -s -X POST http://127.0.0.1:8443/v1/mode \
  -H 'Content-Type: application/json' \
  -d '{"mode":"monitor","signers":["op-1","op-2"]}'
```

**Critère de succès observable** : les denies en closed correspondent aux
would-deny classés à l'étape 2 — aucune surprise ; le rollback rend
`{"mode":"monitor"}` et laisse sa feuille.

**En cas d'échec : STOP** — un deny inattendu en closed = rollback
immédiat, analyse au registre, nouvelle fenêtre d'observation.

#### Étape 5 — Généraliser cellule par cellule

**Prérequis vérifiable** : étape 4 stable sur la première cellule pendant
la durée convenue.

**Commande** :

```bash
# Rejouer les étapes 1-4 par cellule — jamais en vague. Le fencing §7.2
# garantit qu'une époque révoquée (roster, §7.3) invalide les jetons
# pré-émis par incrément : la révocation d'une cellule compromise est
# démontrée par la phase fencing du selftest.
go run ./deploy/selftest -phase fencing
```

**Critère de succès observable** : chaque cellule passe en closed avec
son quorum, sa fenêtre, ses feuilles — la dernière cellule est aussi
prouvée que la première.

**En cas d'échec : STOP** — une cellule qui déroge reste en monitor ; la
campagne continue ailleurs, elle se traite au registre.

# deploy/recovery.fr.md — clé perdue, quorum perdu, k = 1 (issue #199)

_English version: [recovery.md](recovery.md)._

Une cellule qu'on ne sait pas récupérer est une cellule qu'on finit par contourner. Trois choses
le rendent probable si rien n'est écrit : un redémarrage de `pepd` est **refusé tant qu'un quorum
n'a pas signé de nouveau une posture** (#93), un quorum de 1 est configurable
(`TBP_QUORUM_MIN=1`), et un changement gouverné d'un fichier de confiance exige une preuve des
contrôleurs **tels qu'ils étaient attestés** (#218). Perdez les clés : la cellule reste fermée —
par conception. Cette page dit ce qui est possible, dans quel ordre, et ce qui ne l'est *pas*.

> Les tests Go cités sous chaque procédure exercent le vrai code de démarrage de `pepd` et de
> `brokerd` (`setupProvisioning`, `run`). Si une étape ci-dessous diverge, ils cassent : corriger
> le guide ou le code, jamais l'un dans le dos de l'autre. Un guide jamais répété est un pari :
> voir [l'exercice](#lexercice) en fin de page.

## Dans quelle situation êtes-vous ?

Soit **k** = `TBP_QUORUM_MIN` et **n** le nombre de clés de contrôleurs épinglées (entrées de
`TBP_QUORUM_KEYRING_FILE` pour `pepd` ; entrées du `manifest.json` de genèse pour `brokerd`).

| Situation | Condition | Procédure |
|---|---|---|
| **A. Une clé est perdue, le quorum survit** | au moins k clés encore disponibles | [A — remplacer](#a--une-clé-est-perdue-le-quorum-survit) |
| **B. Le quorum est perdu** | moins de k clés disponibles (échelle 1 : la seule clé) | [B — ré-engager](#b--le-quorum-est-perdu) |
| **C. Une clé est volée, pas perdue** | quelconque | [C — compromission](#c--une-clé-est-volée) d'abord, puis A ou B |

Un seul nombre décide entre A et B : **n − k** est le nombre de clés qu'on peut perdre. À
l'échelle 1 (n = 1, k = 1) c'est **zéro** ; un 2-sur-2 n'a pas de rechange non plus (l'avertissement
de démarrage le dit). Prévoir **n ≥ k + 1**, et garder l'une des clés **scellée hors ligne** (une
enveloppe dans un coffre, un HSM dans une autre pièce) : cela ne coûte rien au mécanisme — c'est un
contrôleur épinglé de plus — et transforme B en A.

## Ce qu'une clé perdue avait déjà signé

Rien de ce qu'elle a signé n'est révoqué, et — pour une clé de **contrôleur** — rien de ce qu'elle a signé ne reste *utilisable*. Une clé d'**opérateur** fait exception (dernier point) :

- **Les preuves de quorum** sont liées à une condition et à une cellule, vivent 4 minutes par
  défaut, et (classe W) sont à usage unique y compris après un redémarrage (#206). Aucune ne survit
  à l'incident.
- **Les jetons d'époque** déjà acceptés tiennent jusqu'à l'expiration de leur propre bail
  (10–300 s) ; un nouveau doit se vérifier sous le manifeste en vigueur.
- **Les décisions passées** sont des feuilles signées par la clé de la *cellule*, pas par les
  contrôleurs. Elles restent vérifiables. Retirer un contrôleur n'est pas rétroactif.
- **Les approbations de plan** sont l'exception, et elles sont signées par une clé d'*opérateur*
  (`TBP_OPERATOR_KEYS_FILE`), pas par une clé de contrôleur : un plan approuvé le reste jusqu'à sa propre
  expiration — 1 h par défaut, jusqu'à 24 h. Si une clé d'opérateur est perdue ou volée, aucune vue de la
  console ne liste les plans *approuvés* (`/v1/supervision/arbitration` ne montre que ceux encore en
  attente) : retrouvez-les dans le journal — chaque feuille d'approbation nomme l'identifiant de la clé de
  l'opérateur — et coupez chacun avec `quorumproof planrevoke` ([scale-2.fr.md](scale-2.fr.md), « Couper un
  plan approuvé par erreur »). Avant d'approuver quoi que ce soit à nouveau, **recalculez le hash du plan à
  partir du plan en clair** avec `quorumproof planhash` et ne signez qu'un hash recalculé (#273) : en
  incident, le hash que le broker annonce est précisément ce sur quoi on ne peut pas s'appuyer.

Remplacer une clé ne réécrit donc pas l'histoire. Si la clé a été **volée** plutôt que perdue,
l'histoire compte : voir C.

## A — une clé est perdue, le quorum survit

Exemple : 2-sur-3, une clé perdue, deux disponibles.

**`pepd`** (le trousseau de quorum)

1. Générer la clé de remplacement (sur la machine du signataire) et relever sa clé publique.
2. Éditer le trousseau de quorum : remplacer l'entrée perdue par la nouvelle. `TBP_QUORUM_MIN` ne
   change pas.
3. Recalculer la condition sur **votre propre poste** (#264) —
   `pepd -print-provisioning-condition -cell-vkey cell_log.vkey`, même fichier d'environnement, copie du
   témoin — et la comparer à celle que `pepd` affiche en refusant (`condition à signer :
   provisioning-transition-pepd|from=…|to=…`, #236) : elles doivent être identiques. Faire signer celle que
   **vous** avez calculée par **k des contrôleurs restants** :
   `quorumproof sign -condition '<cette condition>' -cell <cellule> -key … -key … -out proof.json`
4. Poser `TBP_PROVISIONING_TRANSITION_PROOF_FILE` dans `pepd.env`, redémarrer. La preuve est
   vérifiée contre le trousseau **tel qu'attesté au démarrage précédent**, pas contre le fichier qu'on
   vient d'éditer — c'est pourquoi la clé de remplacement ne peut pas signer sa propre admission.
5. La cellule revient `refused` (#93) : reconfirmer la posture avec k signatures issues du **nouveau**
   trousseau. Puis **retirer** la ligne de preuve de `pepd.env`.

**`brokerd`** (le manifeste de genèse — `key_id` est la position de l'entrée, en base 1)

1. **Remplacer la clé perdue sur place. Ne jamais supprimer une entrée, ne jamais réordonner.**
   Supprimer une entrée décale tous les `key_id` suivants, et toutes les signatures déjà faites sous
   l'ancien ordre cessent de se vérifier.
2. Recalculer la condition sur votre poste (`brokerd -print-provisioning-condition -cell-vkey cell_log.vkey`),
   la comparer à celle que `brokerd` affiche en refusant (`provisioning-transition-brokerd|from=…|to=…`),
   la signer par k des contrôleurs restants, poser
   `TBP_PROVISIONING_TRANSITION_PROOF_FILE`, redémarrer, retirer la ligne.
3. Si l'entrée remplacée était l'un des signataires de `epoch0.json` (multi-cellules,
   `TBP_TOPOLOGY=multi`), `brokerd` refuse de démarrer avec `epoch0 refusé` : faire re-signer
   `epoch0.json` par k contrôleurs du **nouveau** manifeste (`scripts/genesis sign` / `renew`), puis
   redémarrer.

`pepd` et `brokerd` portent deux copies du même ensemble de contrôleurs (le trousseau et le
manifeste) : changer les deux, dans la même fenêtre de maintenance.

Vérifié par : `TestPepdLostControllerKeyIsRotatedByTheRemainingQuorum`,
`TestBrokerdLostControllerKeyIsReplacedInPlace`,
`TestBrokerdRemovingAControllerByShiftingRanksIsRefused`,
`TestBrokerdEpoch0SignerReplacedNeedsResign` — y compris le fait qu'après le remplacement, une preuve
signée par la clé perdue et une autre est **refusée**.

## B — le quorum est perdu

Moins de k clés sont disponibles. **Par conception personne ne peut plus rien signer** : ni bascule
de posture, ni transition de provisionnement. La cellule est fermée et le reste ; le mécanisme n'a
pas de porte dérobée, ni de clé de dernier recours sauf si vous en avez épinglé une à l'avance
(voir plus haut).

La reprise n'est alors pas une transition autorisée par l'ancien quorum — il n'existe plus — mais
un **acte d'installation de celui qui administre la machine**, consigné dans le journal :

1. Arrêter `pepd` (et `brokerd`).
2. **Mettre l'ancien témoin de côté, ne pas le supprimer** :
   `mv /var/lib/tbp/pepd-provisioning-witness.json{,.perdu-$(date +%F)}` (idem `brokerd`). C'est la
   preuve de ce que la cellule tenait pour sûr avant.
3. Créer les nouveaux contrôleurs : à l'échelle 1,
   `quorumproof keygen -key /etc/tbp/admin.key.new -keyring /etc/tbp/quorum-keyring.new.json`
   (un **nouveau** fichier de trousseau : `keygen` ajoute à un trousseau existant), puis mettre le
   nouveau trousseau en place. Faire la copie hors machine **maintenant**.
4. Signer une transition avec la ou les **nouvelles** clés : recalculer la condition (`pepd -print-provisioning-condition
   -cell-vkey cell_log.vkey` ; sans témoin elle annonce `state=no-witness` et `provisioning-transition-pepd|from=000…0|to=…`
   — `from` est nul, #236) et la comparer à celle du refus, puis
   `quorumproof sign -condition '<cette condition>' -cell <cellule> -key /etc/tbp/admin.key.new -out proof.json`,
   poser `TBP_PROVISIONING_TRANSITION_PROOF_FILE`, démarrer `pepd`.
5. Sans témoin sur un registre qui a déjà vécu, le démon refuse sans preuve (un témoin effacé n'est
   donc pas une porte ouverte) ; avec une preuve, il **ré-engage** et écrit une feuille
   `re-engaged`. Reconfirmer la posture avec la nouvelle clé, puis retirer la ligne de preuve.

Conséquences, à énoncer avant de le faire :

- **C'est de la confiance à la première utilisation.** Quiconque est root sur la machine et peut
  générer une clé peut faire la même chose. Ce n'est pas un trou que cette procédure ouvre : c'est la
  limite résiduelle du mécanisme (#218) — qui peut effacer le témoin et l'ancien trousseau contrôle la
  cellule. Ce qui vous protège, c'est la **feuille** : le ré-engagement est ajouté au journal (feuille
  de type manifeste, hash seul : qui détient le sel de la cellule la recalcule pour nommer
  l'événement), de sorte qu'un superviseur ou un auditeur peut établir que la racine de confiance a
  changé, et quand. La relire.
- La clé de cellule (`cell_log.key`) est une autre clé et n'est **pas** remplacée ici : l'historique
  reste continu et vérifiable.
- **Échelle ≥ 2 (plusieurs cellules, un superviseur) : non répété.** Ré-engager le quorum d'une
  cellule pendant que ses pairs tiennent l'ancienne époque et l'ancien manifeste est une opération de
  grappe (nouvelle genèse, autres cellules et superviseur prévenus, continuité d'époque). Le mécanisme
  est le même code ; la coordination n'est pas écrite, elle est suivie avec #86 / #33.

Vérifié par : `TestPepdLostQuorumIsRecoveredByReEngagement` — y compris le fait que l'ancienne clé
n'autorise plus rien ensuite, et qu'une preuve signée par la seule nouvelle clé est refusée tant que
l'ancien témoin est là.

## C — une clé est volée

Une clé volée n'est pas une clé perdue : la remplacer ne défait pas ce qu'elle a fait.

1. **Remplacer d'abord** (A) si le quorum survit et que le voleur seul n'atteint pas k. Si k = 1, le
   voleur **est** le quorum : passer à B immédiatement, et tenir la cellule pour compromise jusqu'à
   relecture.
2. **Lire le journal sur la fenêtre** : bascules de posture, transitions de provisionnement et
   ré-engagements (feuilles hash seul : les recalculer avec le sel de la cellule), approbations
   classe W, depuis le dernier moment où vous êtes sûr que la clé était saine.
3. Rejouer le démarrage mesuré (`pepd`) et comparer le témoin de provisionnement à ce que vous
   attendez ; tout écart inexpliqué est un incident, pas un remplacement.

## k = 1 en production

L'échelle 1 **est** k = 1 ([scale-1.fr.md](scale-1.fr.md)) : l'administrateur seul signe, et c'est un
réglage légitime, donc il n'est pas refusé. Ce que font maintenant `pepd` et `brokerd`, c'est le dire
à chaque démarrage, dans le journal, avec le même avertissement pour un quorum sans rechange
(n ≤ k) :

```
pepd: AVERTISSEMENT quorum k=1 (1 contrôleur(s) épinglé(s)) : une seule clé signe tout acte gouverné …
```

À lire comme une liste de contrôle : y a-t-il, *aujourd'hui*, une copie hors machine de la clé ?
Est-ce encore l'échelle où vous voulez être ? Au-dessus de l'échelle 1, k ≥ 2 et n ≥ k + 1 sont la
recommandation ([scales.fr.md](scales.fr.md)). `TBP_QUORUM_MIN` est lu dans l'environnement, mais depuis #224 le témoin de provisionnement
l'atteste (l'entrée `quorum-settings` : k et topologie) : l'abaisser en éditant l'environnement
diverge du témoin, et le changement n'est autorisé que par le k **attesté**, pas par celui que
vous venez d'écrire.

## L'exercice

La procédure n'existe que si on l'a exercée. **Sur une copie de la cellule, jamais sur celle de
production**, au moins une fois par an et après chaque changement de contrôleurs :

1. Copier les fichiers d'environnement, le répertoire du registre et les témoins sur une machine
   d'essai.
2. Sans la clé que vous « avez perdue », jouer **A** si n > k, sinon **B**, avec cette page seule.
3. Chronométrer. Noter chaque étape où il a fallu deviner.
4. Vérifier l'état final : posture reconfirmée, ancienne clé refusée, feuille de ré-engagement ou de
   transition présente, avertissement au démarrage.

Un opérateur qui a perdu une clé doit pouvoir retrouver une cellule opérationnelle avec cette page
seule ; un exercice qui exige autre chose est un défaut de la page, à corriger ici.

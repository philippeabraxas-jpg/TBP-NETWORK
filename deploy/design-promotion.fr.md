# deploy/design-promotion.fr.md — architecture cible : ancrage des bundles et promotion du canari (§7.4)

_English version: [design-promotion.md](design-promotion.md)._

**Statut : conception, non implémentée. À fixer au premier déploiement multi-cellule** (issue #233 ; elle
ferme R-15 de #210). Rien ici n'est un guide à exécuter : cela consigne l'architecture souhaitée pour que le
premier déploiement réponde à ses questions ouvertes au lieu de les redécouvrir.

## Ce qui existe aujourd'hui, sans fard

- `src/cluster/promotion.go` (`PromotionController`) est une **bibliothèque** : elle vérifie un reçu signé —
  la signature de la candidate, le hash du bundle contre le hash ancré, la fenêtre saine — et écrit une feuille
  `KindPromotion` dans les deux cas.
- Le hash ancré et la fenêtre saine viennent d'une interface `MasterAnchorSource` qui n'a **aucune
  implémentation hors tests** (le `masterStub` de la phase `fencing` du selftest), et `NewPromotionController`
  n'a aucun appelant de production.
- L'ancrage du master (`src/registry/anchor.go`) engage la **tête du journal d'une cellule**, pas un bundle ni
  une fenêtre. Le master détient, au mieux, un hash — jamais les octets du bundle.
- `Receipt.ReceivedAt` est signé par la candidate et lu, mais **jamais comparé à rien** (R-15) : l'heure qui
  compte est celle du contrôleur, et elle ne sert qu'à situer la fenêtre.

Conséquence : les guides mono-cellule et échelle 2 ne dépendent de rien de cela ; le guide multi-cellule
([superviseur.fr.md](superviseur.fr.md), étape 5) décrit la bibliothèque et son comportement fail-closed, pas
un service qui tourne.

## Cible : qui détient quoi, qui peut y toucher

| Élément | Détenu par | Écrit par | Lu par |
|---|---|---|---|
| Octets du bundle (la politique signée) | **Magasin de bundles** : adressé par contenu (clé = hash), en lecture seule pour les cellules | la machine de construction/signature seule | les cellules (pour charger), le contrôleur de promotion (pour vérifier) |
| Clé de signature du bundle | HSM, m-sur-n | — | les vérificateurs (clé publique épinglée) |
| **Ancre d'époque** : (époque, `policy_id`, fenêtre saine `[début, fin]`) | le **master chain**, comme enregistrement signé dont le hash est dans une feuille `KindAnchor` | le quorum k-sur-n des contrôleurs (ils *définissent* la fenêtre ; personne ne la mesure) | le contrôleur de promotion, les superviseurs |
| Défis en attente | le contrôleur de promotion, en mémoire | le contrôleur | le contrôleur |
| Verdict de promotion (feuille `KindPromotion`) | le registre propre du contrôleur | le contrôleur | le superviseur |

Principes qui découlent du §7.4 et du reste de la doctrine :

- **L'ancre est publique par construction** (un hash et deux dates), publiée en clair dans un enregistrement
  signé ; seule la *feuille* qui y renvoie est hash-only. Un lecteur doit pouvoir retrouver les valeurs — un
  hash salé seul ne le permet pas.
- **La fenêtre est définie, jamais mesurée par le canari.** L'horloge ou le rapport de santé d'une candidate
  n'est jamais une entrée.
- **Le contrôleur est en lecture seule vers le master** et n'écrit que dans son propre registre. Une partition
  d'avec le master est un refus (c'est déjà le comportement).
- **Aucun composant hors de la machine de construction n'écrit dans le magasin de bundles.**

## Séquence de démarrage d'une candidate

1. Démarrage mesuré et témoin de provisionnement ([cellule.fr.md](cellule.fr.md)) — inchangés.
2. Lire l'**ancre d'époque** de l'époque courante via l'API en lecture seule du superviseur ; vérifier sa
   signature contre les contrôleurs épinglés.
3. Récupérer le bundle **par le hash ancré** dans le magasin ; vérifier le hash et la signature du bundle ;
   démarrer OPA avec cette révision épinglée (#92, #106). Un bundle qui ne correspond pas à l'ancre ne démarre
   jamais.
4. Demander son admission au contrôleur de promotion (ci-dessous).
5. Tant qu'elle n'est pas admise, la cellule ne sert rien comme miroir ; elle reste ce qu'elle était (canari /
   veille).

## Admission : défi-réponse (remplace `ReceivedAt`)

1. La candidate se présente : identifiant de cellule, époque.
2. Le contrôleur émet un **défi** : un nonce aléatoire lié à (cellule, époque), à usage unique, avec une
   expiration **mesurée sur l'horloge du contrôleur**. Les défis en attente sont bornés (saturation = refus,
   jamais d'éviction) et limités en débit par cellule ; un redémarrage les perd — la candidate redemande.
3. La candidate répond par un reçu signé contenant (cellule, époque, hash du bundle, **nonce**) — et, si le
   contrôleur détient le bundle (ci-dessous), une preuve de possession `SHA-256(nonce ‖ bundle)`.
4. Le contrôleur vérifie la signature, le nonce (non consommé, non expiré), le hash contre l'ancre, la fenêtre
   contre sa propre horloge, puis consomme le nonce **avant** d'écrire la feuille d'admission (même ordre que
   les preuves de classe W, #206). Tout échec écrit une feuille de refus et exige une **nouvelle demande**, donc
   un nouveau défi.

Ce que cela corrige : la fraîcheur est prouvée par le contrôleur (un vieux reçu ne peut pas contenir un nonce
qui n'existait pas), le rejeu est impossible, et aucune comparaison d'horloges entre cellules n'est nécessaire.
`ReceivedAt` disparaît : le format du reçu signé change, et le texte du §7.4 de la spec avec lui (EN et FR).

## Possession du bundle : le point de conception ouvert

Aujourd'hui la candidate signe un hash qu'elle peut connaître sans avoir reçu le bundle. Pour prouver la
*possession*, le vérificateur doit avoir de quoi comparer. Deux voies, à choisir au premier déploiement :

- **Le contrôleur détient une copie du bundle**, récupérée dans le magasin par le hash ancré et vérifiée.
  Simple ; suppose que la politique n'est pas confidentielle vis-à-vis du contrôleur (c'est un artefact signé
  que les cellules chargent, donc en général acceptable).
- **Ancrer une racine de Merkle des morceaux du bundle** et faire retourner un morceau aléatoire avec son
  chemin. Pas de copie nécessaire, mais cela change ce qu'est `policy_id` (le hash des règles utilisé partout) :
  un changement de protocole, déconseillé sauf si la confidentialité l'impose.

Dans les deux cas, les **octets exacts** que `policy_id` hache doivent être définis une fois pour toutes
(aujourd'hui : un hash des sources Rego, pas de l'archive `tar.gz` qui circule).

## Décisions laissées au premier déploiement multi-cellule

1. Où tourne le contrôleur de promotion (le superviseur indépendant est l'endroit naturel : il lit déjà le
   master et n'écrit que dans son propre registre).
2. Le format de publication de l'ancre d'époque et qui la signe (le quorum des contrôleurs).
3. Les octets exacts derrière `policy_id`, et laquelle des deux options de possession.
4. Quelle autorité définit la fenêtre saine, et à quelle fréquence.
5. Les limites de débit et la taille de l'ensemble des défis en attente.
6. Le comportement quand le master est injoignable au démarrage (aujourd'hui : refus — le garder, et dire
   comment un opérateur reprend).

D'ici là : la bibliothèque reste telle quelle, rien ne prétend plus qu'elle ne fait, et R-15 reste ouverte sous
#233.

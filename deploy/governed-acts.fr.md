# Les actes gouvernés : ce que chacun coûte, et pourquoi

_English version: [governed-acts.md](governed-acts.md)._

TBP demande un effort différent pour deux sortes d'acte, volontairement.

- Un acte qui **restreint** rend la cellule plus stricte : il ferme, coupe, refuse, retire. Le faire à tort coûte
  un peu de disponibilité, et se défait. Il doit être **facile et rapide** : une personne, même quand la plupart
  des contrôleurs sont injoignables.
- Un acte qui **élargit** laisse la cellule autoriser plus : il approuve, rouvre, reprend, cède l'autorité. Le
  faire à tort, ou sous contrainte, laisse passer ce qui devait rester bloqué. Il doit être **difficile** :
  plusieurs signatures de plusieurs clés.

Quand un acte pourrait être l'un ou l'autre, il compte comme un **élargissement**, sauf preuve qu'il ne fait que
durcir. Le test pratique quand on ajoute un acte : quel est le pire qu'un appel erroné ou forgé puisse faire ? Si
la réponse est « la cellule applique les règles qu'elle a déjà », il restreint.

Cette page liste chaque acte que la cellule prend aujourd'hui, de quel côté il est, et ce qu'il exige. C'est la
référence à lire avant d'en ajouter un.

## Les actes

| Acte | Où | Côté | Ce qu'il exige |
|---|---|---|---|
| Fermer le réseau (monitor → closed) | `pepd` `POST /v1/mode` | restreint | `TBP_MODE_RESTRICT_QUORUM_MIN` signatures de contrôleurs (défaut 1, jamais plus que k) ; laisse sa propre feuille et lève `mode-closed-reduced-quorum` |
| Le rouvrir (closed → monitor), sortir de `refused` | `pepd` `POST /v1/mode` | élargit | k signatures de contrôleurs, toujours |
| Soumettre un plan | `brokerd` `plan/submit` | neutre : rien ne s'exécute avant l'approbation | à partir de k = 2, la signature d'une clé qui tient `submit` ; le soumetteur n'approuve jamais ce plan |
| Approuver un plan | `brokerd` `plan/approve` | élargit | classe F ou W : k clés distinctes qui tiennent `approve` ; classe I : une ; jamais la clé du soumetteur |
| Révoquer un plan | `brokerd` `plan/revoke` | restreint | une signature d'une clé qui tient `revoke` |
| Refuser une demande dégradée | `brokerd` `degraded/decide` | restreint | une signature d'une clé qui tient `arbitrate` **ou** `revoke` |
| Approuver une demande dégradée | `brokerd` `degraded/decide` | élargit (admet cette seule demande) | une signature d'une clé qui tient `arbitrate` |
| Signaler sa présence | `brokerd` `degraded/presence` | neutre | une clé qui tient `arbitrate` |
| Lever une condition fail-closed de classe W | `pepd` `POST /v1/failclosed/clear` | élargit | k signatures de contrôleurs liées à la condition |
| Lever une condition fail-closed de classe F ou I | `pepd` `POST /v1/failclosed/clear`, ou automatiquement après sondes | élargit | rien d'autre que l'accès au socket d'administration (spec §5.3 : seule la classe W exige un quorum) ; la levée automatique est refusée pour la classe W |
| Renouveler le bail d'époque (multi-cellule) | `brokerd` `POST /v1/epoch/renew` | élargit : garde l'autorité de la cellule vivante | le quorum des contrôleurs, signé hors bande |
| Promouvoir la cellule miroir | `brokerd` `mirror/promote` | élargit : cède l'autorité | un reçu signé par la cellule miroir et l'ancre du quorum |
| Changer ce que la cellule fait confiance (règles, fichiers de confiance, échelle, posture) | témoin de provisionnement, au démarrage | l'un ou l'autre | k signatures de contrôleurs liées au changement exact, et un redémarrage à froid : **le même coût dans les deux sens** (voir plus bas) |

Les rôles se posent par clé dans `operators.json` ([scale-2.fr.md](scale-2.fr.md) étape 3). Une clé qui signe pour
un rôle qu'elle n'a pas est refusée avec une raison nommée, et le refus laisse une feuille.

## Ce qui n'est pas encore asymétrique

- **Durcir les fichiers de confiance coûte autant que les relâcher.** Retirer une clé d'opérateur volée, ou
  relever `k`, est une transition de provisionnement comme une autre : k contrôleurs et un redémarrage à froid. En
  attendant, la clé volée se neutralise plan par plan (`plan/revoke`, une signature), mais elle reste dans le
  trousseau. Une transition qui prouve qu'elle ne fait que durcir, et exige donc moins de signatures, n'est pas
  construite.
- **Une condition fail-closed de classe F ou I se lève sans preuve.** C'est ce que dit la spec (§5.3), et le
  socket d'administration est le contrôle d'accès. Si une cellule ne le veut pas, enregistrer la condition en
  classe W.
- **Approuver une demande dégradée exige une signature.** Elle admet une demande, une fois, qui passe ensuite par
  la chaîne habituelle. Une cellule qui veut plus peut ne garder `arbitrate` que sur une clé et surveiller les
  feuilles.

## Ajouter un acte

1. Dire de quel côté il est, avec le pire qu'un appel forgé puisse faire.
2. Donner à ce côté son prix : restreindre, c'est une clé ou un quorum réduit ; élargir, c'est k clés.
3. Mettre le prix dans le code qui l'applique (`brokerd`, `pepd`), jamais dans une enveloppe ou un script qu'un
   appel direct contournerait.
4. Laisser une feuille pour l'acte, et une pour chaque refus.
5. L'ajouter à ce tableau.

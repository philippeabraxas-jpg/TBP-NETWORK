## Résumé

<!-- Ce que change la PR et pourquoi. -->

## Conformité

- [ ] Cette PR **change ce que TBP couvre** (nouveau mécanisme, nouvelle limite, trou trouvé ou fermé) → `tbp-compliance/` est mis à jour dans la même PR (ligne ✅ avec le mécanisme et ses limites, 🔴 avec son issue, ou ⚪ avec le motif et le guide de fermeture pour le déploiement).
- [ ] Sinon : aucun impact sur le catalogue.
- [ ] `python3 tbp-compliance/check_catalog.py` passe.

## Si cette PR ferme une issue de sécurité

Plusieurs issues de sécurité ont été fermées avant que le problème soit entièrement réglé (#110 en deux fois, #126, #129). Pour celles-ci :

- [ ] L'issue liste ses **critères de fermeture**, et chacun est coché ici avec sa preuve (test, commande, lien).
- [ ] Un test **échoue si on retire le correctif** (mutant), et le cas voisin autorisé passe.
- [ ] Le correctif a été **vérifié par quelqu'un d'autre que son auteur** (nom du relecteur : …).
- [ ] Guides `deploy/` (EN **et** FR) et catalogue de conformité à jour.
- [ ] Ce qui n'est **pas** corrigé est écrit ici et a son issue.

## Test plan

- [ ]

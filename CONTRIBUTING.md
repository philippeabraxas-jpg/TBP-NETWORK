# Contribuer à TBP-NETWORK

## État du dépôt

Le code (`config/`, `src/`, `policies/`, `lab/`, `tests/`, `.github/`) est
sous licence fermée (voir `LICENSE`) — pas de contributions externes
acceptées pour l'instant. La documentation (`docs/`, `figs/`) est en
CC BY 4.0 (voir `docs/LICENSE`) : les corrections et suggestions sur la
spec, le glossaire ou les figures sont bienvenues par issue ou pull
request.

## Règles pour toute modification de `docs/spec-v1.4.2.md`

1. **Le glossaire de normalisation (§14) est la source de vérité
   terminologique.** Toute modification qui introduit un nouveau concept
   doit soit réutiliser un terme canonique existant, soit l'ajouter au
   glossaire — jamais un synonyme non mappé glissé dans le corps du texte.
   `docs/glossaire.md` doit rester identique mot pour mot au tableau du §14.
2. **Toute référence normative (RFC, draft IETF, norme) doit être vérifiée
   avant commit** — numéro ET titre, pas seulement le numéro qui "sonne
   juste". Une correction de ce type a déjà eu lieu (voir §16, v1.4.2) :
   RFC 9578 avait été citée à tort pour « Proof of Transit » (c'est en
   réalité *Privacy Pass Issuance Protocols* — « Proof of Transit » n'a
   jamais été publié en RFC).
3. **Toute modification de version doit ajouter une ligne au changelog
   (§16)**, jamais écraser silencieusement le contenu d'une version
   précédente — cohérent avec la doctrine « dater la confiance » du §15.
4. **Numérotation des sections** : certaines sections commencent à `.2`
   (§3, §6) plutôt qu'à `.1` — c'est hérité des révisions précédentes, pas
   une erreur à « corriger » en renumérotant tout le document (ça casserait
   les renvois croisés internes et externes).

## Rapporter un problème

Utiliser les templates dans `.github/ISSUE_TEMPLATE/`. Pour un problème de
sécurité sur l'implémentation (pas la spec), ne pas ouvrir d'issue publique
— contacter l'auteur directement.

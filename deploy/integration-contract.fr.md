# deploy/integration-contract.fr.md — ce que l'intégrateur doit savoir (issue #210)

_English version: [integration-contract.md](integration-contract.md)._

Des limites et des obligations que le code ne peut pas faire respecter à votre place, trouvées par la
revue red team suivie dans #210 et écrites ici pour que personne ne les découvre en production. Aucune
n'est un défaut à corriger dans TBP : chacune est soit un contrat que l'intégration doit honorer, soit
une borne contre laquelle dimensionner, soit un choix de conception qui a un coût.

## 1. Le sceau objet ne vaut que ce que le service recalcule (R-4)

Le sceau objet-capacité (claim −5, §4.4(2)) lie une autorisation à l'**objet métier exact** pour lequel
elle a été émise : un jeton qui porte un sceau n'autorise que le corps ou l'état qui y correspond au
hachage (`ReasonSealMismatch` sinon).

Que cela tienne dépend de **qui calcule le sceau** :

| Chemin | Qui calcule le sceau | Ça tient ? |
|---|---|---|
| Proxy transparent (`pepd` devant un backend HTTP) | `pepd` lui-même : SHA-256 du corps qu'il relaie (#108) | **Oui** — l'agent ne choisit rien |
| `POST /v1/evaluate`, et mode structuré de `brokerd` (`object_seal` dans l'intention) | **Le présentant** (l'agent fournit `object_seal` ; l'émetteur le recopie dans le jeton ; le validateur compare le sceau du jeton à celui de la requête) | **Seulement si le service le recalcule** |

Sur le second chemin, les deux valeurs sont choisies par le présentant, donc égales par construction :
le contrôle ne prouve rien sur l'objet réel. La capacité n'est réelle que si le **service qui exécute
l'action recalcule `ComputeObjectSeal` (`src/pep/object_capability.go`) sur l'état réel et le compare
au claim −5 du jeton** (ou soumet à `evaluate` son propre sceau recalculé), comme le fait côté serveur
l'intégration PostgreSQL. C'est donc un **contrat d'intégration obligatoire** :

- Si votre service exécute une action sur un objet métier et s'appuie sur le sceau, il recalcule le
  sceau à partir de l'objet réel au moment de l'exécution. Un sceau reçu de l'agent n'est jamais cru
  tel quel.
- S'il ne peut pas recalculer (un service HTTP générique sans adaptateur), ne pas compter le sceau
  comme un contrôle : s'appuyer sur le chemin proxy, sur des règles OPA portant sur `resource`, et sur
  le confinement propre de l'exécuteur ([execution-sandbox.fr.md](execution-sandbox.fr.md)).

## 2. Les bornes se composent, elles ne s'additionnent pas (R-1, R-5)

Chaque borne est raisonnable seule ; leur composition est plus petite que chacune :

- **Intention : 4096 octets de JSON.** `quorum_proof` (≤ 4096 octets bruts) et `plan_binding`
  (≤ 4135 octets bruts) voyagent **encodés en hexadécimal dans cette intention**, ce qui les double.
  Une preuve ou un binding ne peut pas atteindre son propre maximum : au-delà d'environ 2 Kio bruts — de
  l'ordre de quelques co-signataires d'un quorum de classe W — la requête est refusée
  (`request-invalid`) et l'opérateur voit un refus opaque. Dimensionner le quorum (k et encodage des
  signatures) contre cette borne, pas contre 4096.
- **Jeton : 1024 octets sur le fil.** Le jeton porte sujet, action, identifiant de cellule, `resource`
  (≤ 1024) et, avec un passeport, `quota.resource` (≤ 1024) aussi. Une composition légitime peut dépasser
  le plafond du fil bien avant que l'un des champs n'atteigne son propre maximum (estimation de la revue :
  `resource` ≳ 600 octets avec un passeport) ; l'émetteur refuse alors avec `ErrTokenTooLarge`. C'est
  fail-closed, mais c'est un déni de service fonctionnel pour des requêtes légitimes : garder des
  identifiants de ressource courts (des identifiants, pas des chemins ni des requêtes), et mettre ce qui
  est long dans les paramètres de l'action, liés par `plan_binding`.

## 3. Notes de friction (R-6, R-2)

- **La classe d'action est par agent, pas par requête (R-6).** Le registre résout une classe pour un
  agent (#125) ; un agent qui mêle lectures et écritures d'infrastructure subit le palier le plus strict,
  liaison de plan comprise, sur **toutes** ses requêtes. C'est voulu (la classe n'est jamais prise de
  l'agent). La sortie est opérationnelle : enregistrer des agents distincts par activité, ou affiner en
  Rego avec `SkillInput` (voir le paquet `risk_tier`). Compté comme friction (§9.1).
- **`quota.resource` n'est pas la `resource` de l'action (R-2).** La ressource du passeport (ce qui est
  compté) et celle de l'action (ce qui est touché) sont distinctes exprès — le plan de données n'est pas
  la route d'API. Ce qui les relie, c'est la règle d'enveloppe OPA et le plafond du registre. Les auteurs
  de politique écrivent la règle qui les apparie s'ils les veulent égales.

## 4. Ce que font et ne font pas les identifiants de pair (R-20)

`SO_PEERCRED` sur la socket d'OPA vérifie l'**UID** du pair à chaque connexion. Un attaquant qui tourne
déjà sous le même UID peut tuer OPA et re-lier la socket : la vérification **retarde** une imposture, elle
ne l'empêche pas. Faire tourner OPA sous son propre compte, avec le mode de la socket et la propriété du
répertoire réglés pour que seuls `pepd` et OPA la partagent (voir [cellule.fr.md](cellule.fr.md)), et
compter sur le démarrage mesuré (#112) et le témoin de provisionnement (#192) pour ce qu'un attaquant
disposant de ce compte pourrait changer.

## 5. Les corps de requête exacts, et comment l'agent les apprend (#289)

Tout corps JSON que la cellule lit d'un agent, d'un proxy ou d'un opérateur est décodé
**strictement** (`src/strictjson`). Le décodeur refuse ce que le décodeur standard de Go accepte
en silence et qu'un proxy, un WAF, un journal ou un outil de revue lirait autrement :

- une **clé en double**, à n'importe quelle profondeur (le décodeur standard garde la dernière) ;
- une clé qui n'est pas **exactement** un nom de champ documenté — champ inconnu, mais aussi
  casse différente (`"ACTION"` n'est pas `"action"`) ;
- du **contenu après** le document (`{…} {…}`) ;
- de l'**UTF-8 invalide**.

Un client légitime n'envoie que les champs documentés, avec leur casse exacte, en un seul document.

| Endpoint (plan) | Corps — noms de champs exacts |
|---|---|
| `POST /v1/actions` (`brokerd`, données) | `subject`, `intent` — deux chaînes |
| …`intent` en mode structuré (un document JSON **dans** cette chaîne, décodé strictement lui aussi) | `action`, `resource` (obligatoires) ; optionnels `class` (0–3), `object_seal` (hex, 32 octets), `quota` {`resource`, `operation`, `volume_max`, `window_s`}, `quorum_proof` (hex), `plan_binding` (hex) |
| `POST /v1/evaluate` (`pepd`, données) | `token` (base64), `action`, `resource` ; optionnel `object_seal` (hex) |
| `POST /v1/passport/consume` (`pepd`, données) | `token` (base64), `n` |
| `POST /v1/mode` (`pepd`, admin) | `mode`, `expiry` (secondes Unix), `signatures` [{`key_id`, `signature`}] — la forme qu'écrit `quorumproof` |
| `POST /v1/failclosed/clear` (`pepd`, admin) | `condition` ; en classe W aussi `expiry`, `signatures` |

Les autres corps (`plan/submit`, `plan/approve`, `plan/revoke`, les registres de provisionnement)
étaient déjà stricts (#241, #274).

**Comment l'agent apprend la bonne structure.** Il n'y a pas d'endpoint de schéma : ce tableau est
le contrat. Ce que l'agent reçoit à l'exécution, c'est une **raison lisible par une machine** qui
dit quoi corriger, jamais le contenu de sa demande :

```json
{"allow":false,"reason":"request-invalid",
 "detail":{"code":"unknown-field","key":"Subject","accepted":["intent","subject"]}}
```

- **Corps** mal formé → HTTP 400 ; `reason` `request-invalid` (`brokerd`) ou `"error":"corps JSON
  illisible"` (`pepd`), avec `detail`.
- **Intention** mal formée (le JSON dans `intent`) → HTTP 200, `allow:false`, `reason`
  `translation-failed`, avec `detail`.
- `detail.code` vaut `duplicate-key`, `unknown-field` (inconnu **ou** casse inexacte ; `accepted`
  liste les noms exacts valides à cet endroit, `path` situe un objet imbriqué), `trailing-content`,
  `invalid-utf8`, `syntax`, `type`, et pour l'intention structurée `missing-field` (`action` ou
  `resource` absent) et `out-of-range` (`class`). `key` est le **nom** fautif, tronqué à 64
  octets ; aucune valeur de la demande n'est jamais renvoyée.
- Un refus de **décision** (OPA, quorum, plan, enveloppe…) ne porte aucun `detail` : ce serait un
  oracle sur la politique. Seule la *forme* de la demande est expliquée.

**Traducteur dégradé (§4.5).** Quand la cellule tourne avec la garde du traducteur
(`TBP_TRANSLATOR_GUARD=1`, `deploy/cellule.fr.md`), un refus peut concerner le *traducteur* et non la
demande : `reason` `translation-failed` **sans** `detail` veut dire « le traducteur est indisponible
et rien n'admet cette demande maintenant » — réessayer plus tard, ne pas réécrire la demande. Deux
autres issues existent quand l'arbitrage humain est câblé (`TBP_ARBITRATION=1`), pour les systèmes
**standard** seulement :

- `reason` `arbitration-pending`, `allow:false`, avec `arbitration_id` — **pas** un refus définitif :
  la demande est en file pour un arbitre humain. `arbitration_id` est
  `SHA-256("tbp-degraded-intent-v1" ‖ u16be len(sujet) ‖ sujet ‖ intention)` sur les **octets
  exacts** envoyés — le recalculer soi-même, l'arbitre signe CE hash. Une fois l'arbitre
  d'accord, **renvoyer la demande à l'identique** : elle est admise une fois (l'approbation est à
  usage unique et expire), puis jugée par toute la chaîne comme n'importe quelle autre (OPA, quorum,
  plan, contrats — une approbation ne lève que l'admission du traducteur). Renvoyer avant la
  décision rend de nouveau `arbitration-pending`, sans doublon.
- `reason` `arbitration-refused` — l'arbitre a refusé cette demande.

La file ne retient que ce hash, jamais le contenu de la demande.

Une intégration placée entre un agent LLM et la cellule doit rendre `detail` tel quel à l'agent :
il est écrit pour que l'agent corrige sa demande suivante (`accepted` est la liste des noms qu'il
peut employer à cet endroit).

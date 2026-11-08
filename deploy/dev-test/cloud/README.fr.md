# deploy/dev-test/cloud — les trois machines du test de site, dans un cloud, pas à pas

_English version: [README.md](README.md). Fait partie de [deploy/dev-test](../README.fr.md)._

> **Pas pour la production.** Trois machines jetables, aucune donnée réelle. Tout se supprime en supprimant un seul
> groupe (Azure) ou une seule pile (AWS). Les modèles ouvrent **une** seule chose à Internet — ssh, depuis la **seule**
> adresse que vous donnez — et rien d'autre.

## En clair

**Le but.** TBP est fait pour être lancé, et attaqué, avant d'être cru ([deploy/dev-test](../README.fr.md)). Le test qui
compte est le test *site* : **trois machines** qui se parlent — un agent (M3) demande à la cellule (M1) s'il peut agir,
puis montre ce qu'il a reçu à un serveur applicatif (M2) — parce que c'est la seule façon de voir si l'ensemble marche sur
un vrai réseau. Peu de gens ont trois machines de rechange. Ce dossier vous permet de **les louer quelques heures dans un
cloud (Azure ou AWS), de faire le test, puis de tout supprimer**, pour quelques euros ou dollars.

**Ce qu'il contient.**

| Quoi | Ce que c'est |
|---|---|
| [`azure.bicep`](azure.bicep), [`aws.cfn.yaml`](aws.cfn.yaml) | Un *modèle* : un fichier texte qui décrit les machines voulues — combien, quel système, quel réseau, quelles portes ouvertes. Vous le remettez à Azure ou AWS, qui construit exactement cela. Une recette : la même recette donne le même résultat |
| cette page, [azure.fr.md](azure.fr.md), [aws.fr.md](aws.fr.md) | Les étapes pour quelqu'un qui n'a jamais utilisé un cloud : le compte, une clé ssh sûre, la création des machines, la connexion, la suppression |
| [`test_templates.py`](test_templates.py) | Un contrôle automatique, lancé par la CI du projet, que les modèles tiennent leurs promesses : ce qui est ouvert, et à qui |

**Comment ça marche, en quatre idées.**

1. **Le cloud vous donne des ordinateurs vides.** Le modèle demande trois machines Linux (Debian 12) sur un même réseau
   privé, derrière un pare-feu. Rien de TBP n'y est encore : vous l'installez à l'étape suivante, avec les commandes de
   [site.fr.md](../site.fr.md), pour que ce que vous testez soit exactement ce que cette page documente.
2. **Vous les pilotez depuis votre propre ordinateur, par ssh.** `ssh` est un terminal texte à travers le réseau. Votre
   ordinateur est le clavier et l'écran des trois machines — comme la console web d'un hyperviseur, en texte — et vous
   ouvrez **trois terminaux, un par machine**. TBP n'a pas d'administration à distance, exprès : signer un plan ou fermer
   le point de contrôle se fait *sur* la machine, et ssh est le moyen de s'y asseoir.
3. **Le pare-feu n'ouvre qu'une porte** : ssh, depuis la seule adresse que vous donnez. Les trois machines se parlent sur
   les trois ports du test (8443 la cellule, 9000 l'application, 9100 la console) ; personne d'autre ne les atteint.
4. **Vous regardez dans un navigateur.** Une console temps réel montre le trajet de chaque requête à travers les trois
   machines, l'état de chaque composant et la latence de chaque étape. Elle est en lecture seule, et on l'atteint par un
   tunnel ssh, pas par Internet.

**Ce que vous obtenez.**

La console temps réel est décrite, avec une image, dans [console.fr.md](../console.fr.md). Un rapport d'un vrai passage —
mesures et capture de la console — sera ajouté quand le test aura été fait sur Azure **et** sur AWS.

- **M1, la cellule** : décide qui peut faire quoi, et signe un jeton pour cela. **M2, un serveur** : son point de contrôle
  (`pepd`) vérifie le jeton et le serveur n'agit que s'il le dit. **M3, un agent** : demande, puis présente ce qu'il a reçu.
- Un test à suivre pas à pas ([site.fr.md](../site.fr.md)) : demander sans approbation et être refusé ; approuver comme
  opérateur, sur M1 ; redemander et être exécuté ; rejouer un jeton, en forger un, fermer puis rouvrir le point de
  contrôle. Dans la console, chaque requête montre **quel composant l'a arrêtée, et pourquoi**, et le temps de chaque étape.
- Ensuite vous pouvez essayer de le casser (« L'attaquer » dans `site.fr.md`), et nous envoyer ce que vous avez trouvé avec
  `report` — vos chiffres, qui sont le but de l'exercice.
- Quand vous avez fini, **une seule commande supprime tout**. Environ 3 à 4 euros ou dollars par jour pendant que les trois
  machines tournent (le prix varie selon la région) : arrêtez-les ou supprimez-les quand vous ne testez pas.

**Ce que ce n'est pas.** Pas de la production : clés jetables, un interrupteur de développement sur la cellule, aucune
donnée réelle. Pas un service géré : les machines sont à vous tant que vous les gardez. Pas durci pour l'Internet ouvert :
c'est pourquoi seule votre adresse peut les atteindre.


| | Azure | AWS |
|---|---|---|
| Guide | **[azure.fr.md](azure.fr.md)** | [aws.fr.md](aws.fr.md) |
| Modèle | [`azure.bicep`](azure.bicep) | [`aws.cfn.yaml`](aws.cfn.yaml) |
| Machines | 3 × `Standard_B2s` (2 CPU, 4 Go), Debian 12 | 3 × `m6i.large` (2 CPU, 8 Go), Debian 12 |
| Identifiant sur les machines | `tbp` | `admin` |
| Tout supprimer | `az group delete` | `aws cloudformation delete-stack` |

Prenez celui sur lequel vous avez des crédits. Le test est le même des deux côtés : seule la première partie (créer les
machines) change, et l'étiquette donnée à `init` (`--env`) nous dit de quel cloud vient votre rapport.

## Ce que vous obtenez

```
 votre ordinateur ──ssh (22, depuis votre seule adresse)──► les trois adresses publiques
 (et la console, par un tunnel ssh)

 réseau privé 10.20.0.0/24
   M1  10.20.0.10   la cellule              :8443 (agents, TLS mutuel)   :9100 (console temps réel)
   M2  10.20.0.11   serveur applicatif      :9000 (l'application)
   M3  10.20.0.12   l'agent                 —
```

| Flux | Port | Autorisé |
|---|---|---|
| votre ordinateur → chaque machine | 22/tcp | depuis **votre adresse** seulement |
| les machines → M1 | 8443/tcp, 9100/tcp | entre les trois machines seulement |
| les machines → M2 | 9000/tcp | entre les trois machines seulement |
| tout le reste, depuis Internet ou entre les machines | — | refusé |

Deux conséquences que vous remarquerez. **La console temps réel n'est pas ouverte à Internet** : vous l'atteignez par un
tunnel ssh (plus bas), ce qui garde aussi sa clé hors du réseau en clair. Et **les paquets passent par votre ordinateur**,
pas de machine à machine, parce que les machines ne peuvent pas se connecter l'une à l'autre en ssh (les paquets
contiennent les clés privées du test : vous supprimez votre copie ensuite).

## Avant de créer quoi que ce soit

**1. Votre adresse publique.** L'adresse sous laquelle Internet vous voit : cherchez « what is my IP » dans un
navigateur. Elle ressemble à `203.0.113.7`. Si vous changez de réseau (maison, bureau, téléphone), elle change :
redéployez ou modifiez la règle (chaque guide dit comment).

**2. Une clé ssh**, sur votre ordinateur. Dans *PowerShell* (Windows 10/11) ou un terminal (macOS, Linux) :

```
ssh-keygen -t ed25519 -f "$HOME/.ssh/tbp-devtest" -C tbp-devtest
cat "$HOME/.ssh/tbp-devtest.pub"
```

Mettez-y une phrase secrète. La seconde commande affiche **une ligne** qui commence par `ssh-ed25519` : c'est la clé
*publique*, celle dont le cloud a besoin. Le fichier sans `.pub` est privé : il ne quitte jamais votre ordinateur. Si
`.ssh` n'existe pas, créez-le d'abord (`mkdir "$HOME/.ssh"`).

**3. Une alerte de coût.** Les crédits s'épuisent, et les machines coûtent tant qu'elles tournent. Environ 3 à 4 euros
ou dollars par jour pour les trois Azure `Standard_B2s`, environ 8 pour les trois AWS `m6i.large` (vérifiez le prix dans votre portail : il varie selon la région). Créez un budget avec
une alerte par e-mail avant la première machine ([azure.fr.md](azure.fr.md#1-avant-les-machines),
[aws.fr.md](aws.fr.md#1-avant-les-machines)) et **arrêtez ou supprimez les machines quand vous ne testez pas**.

## Ensuite, quand les trois machines existent

Les deux guides finissent ici. `<M1pub>`, `<M2pub>`, `<M3pub>` sont les adresses **publiques** affichées à la fin du
modèle ; `<login>` vaut `tbp` (Azure) ou `admin` (AWS) ; `<clé>` vaut `"$HOME/.ssh/tbp-devtest"`. Dans le test, les
machines utilisent leurs adresses **privées** `10.20.0.10`, `.11`, `.12`, jamais les publiques.

**1. M1 — la cellule.** `ssh -i <clé> <login>@<M1pub>`, puis le bloc M1 de [site.fr.md](../site.fr.md#déployer) avec
`<M1>` = `10.20.0.10` (les paquets, OPA, Go, le clone), et :

```bash
scripts/devtest/site.sh m1 init --address 10.20.0.10 --env "<cloud>, <taille>, <région>"     # p. ex. "azure, Standard_B2s, francecentral"
scripts/devtest/site.sh m1 up
```

Arrêtez-vous avant les deux lignes `scp` de `site.fr.md` : elles ne marchent pas ici. Faites plutôt ceci, **depuis votre
ordinateur** (un second terminal) :

```
scp -i <clé> <login>@<M1pub>:tbp-site-m1/packs/m2.pack.tgz .
scp -i <clé> <login>@<M1pub>:tbp-site-m1/packs/m3.pack.tgz .
scp -i <clé> m2.pack.tgz <login>@<M2pub>:
scp -i <clé> m3.pack.tgz <login>@<M3pub>:
```

puis supprimez les deux fichiers de votre ordinateur (`rm m2.pack.tgz m3.pack.tgz` ; `Remove-Item` dans PowerShell) :
`m3.pack.tgz` contient les clés privées des agents du test.

**2. M2.** `ssh -i <clé> <login>@<M2pub>`, puis le bloc M2 de `site.fr.md` avec `<M2>` = `10.20.0.11`.

**3. M3.** `ssh -i <clé> <login>@<M3pub>`, puis le bloc M3 avec `--app http://10.20.0.11:9000`. `site.sh m3 check` doit se
terminer par `site M3: the plumbing works`.

**4. La console temps réel, dans votre navigateur.** `m1 up` a affiché une adresse du genre
`http://10.20.0.10:9100/?key=…` : c'est une adresse *privée*. Ouvrez un tunnel depuis votre ordinateur, dans un terminal
que vous laissez ouvert :

```
ssh -i <clé> -N -L 9100:10.20.0.10:9100 <login>@<M1pub>
```

et ouvrez dans le navigateur la même adresse avec **`localhost`** à la place de `10.20.0.10` :
`http://localhost:9100/?key=…`. [console.fr.md](../console.fr.md) dit comment lire la page. (N'ouvrez pas le port 9100 à
Internet : c'est du HTTP en clair.)

**5. Tester.** Suivez le tableau « Quoi tester » de [site.fr.md](../site.fr.md), puis « L'attaquer », puis `report` sur
chaque machine ([Nous dire ce que vous avez trouvé](../site.fr.md#nous-dire-ce-que-vous-avez-trouvé)) : l'étiquette donnée
à `init` dit que c'était ce cloud.

## Quand quelque chose ne marche pas

| Symptôme | Cause et remède |
|---|---|
| `Permission denied (publickey)` | mauvais identifiant (`tbp` sur Azure, `admin` sur AWS), mauvais fichier de clé, ou clé publique collée avec un retour à la ligne ou coupée. Comparez `cat "$HOME/.ssh/tbp-devtest.pub"` avec ce que vous avez donné |
| `ssh` reste figé, puis `timed out` | votre adresse n'est plus celle que vous avez donnée (elle a changé), ou la machine est arrêtée. Vérifiez l'adresse et l'état de la machine dans le portail |
| `m3 check` n'atteint ni la cellule ni l'application | le pare-feu n'est pas venu avec le modèle (machines créées à la main ?), ou M1/M2 ne sont pas `up`. `site.sh m1 listeners` montre ce qui écoute |
| la page de la console ne s'ouvre pas | le tunnel ne tourne pas (il lui faut son terminal ouvert), ou vous avez pris l'adresse privée au lieu de `localhost` |
| `m1 init` échoue avec `undefined: pkcs11.Attribute` | M1 n'a pas de compilateur C (Go désactive alors seul le code C). `sudo apt-get install -y gcc libc6-dev`, puis relancez `init` (il n'a rien laissé derrière lui) |
| après arrêt puis démarrage des machines, rien ne répond | les processus du test ne redémarrent pas seuls : relancez `up` sur M1 et M2 (un redémarrage de `pepd` revient en *refused* par construction, voir [site.fr.md](../site.fr.md)). Arrêter puis démarrer des machines cloud, **nous ne l'avons pas testé** : si `up` échoue, supprimez et redéployez |

## Ce qui a été vérifié, et ce qui ne l'a pas été

Le test lui-même (`site.sh`) tourne, en CI, sur un seul hôte qui simule les trois machines. **Le modèle Azure a été
déployé une fois pour de vrai** (Suède Centre, `Standard_D2s_v5`, novembre 2026), jusqu'aux trois machines up, `m3 check`
qui passe et la console temps réel ouverte, puis les étapes 1 à 14 de `site.fr.md` — voir le
[brouillon de rapport du 2026-11-08](../reports/2026-11-08-azure.fr.md). Ce premier passage a trouvé deux choses désormais écrites ici : la machine qui compile la cellule a besoin d'un
compilateur C, et un abonnement récent peut se voir refuser certaines régions et tailles
([azure.fr.md](azure.fr.md#4-créer-les-machines)). **Le modèle AWS n'a pas été exécuté sur un vrai compte** : son guide
commence par une commande de *validation* qui vérifie le modèle sans rien créer. Si une étape d'ici ne correspond pas à
votre portail (les noms bougent), dites-le nous dans une [issue dev-test](../README.fr.md#nous-dire-ce-que-vous-avez-trouvé).

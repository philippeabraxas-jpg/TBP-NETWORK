# deploy/dev-test/cloud — les trois machines du test de site, dans un cloud, pas à pas

_English version: [README.md](README.md). Fait partie de [deploy/dev-test](../README.fr.md)._

> **Pas pour la production.** Trois machines jetables, aucune donnée réelle. Tout se supprime en supprimant un seul
> groupe (Azure) ou une seule pile (AWS). Les modèles ouvrent **une** seule chose à Internet — ssh, depuis la **seule**
> adresse que vous donnez — et rien d'autre.

[site.fr.md](../site.fr.md) dit à quoi servent les trois machines et quoi tester. Ce dossier vous donne les trois machines
dans un cloud **sans connaître le cloud** : un modèle crée le réseau, le pare-feu et les machines ; vous suivez ensuite
`site.fr.md`.

| | Azure | AWS |
|---|---|---|
| Guide | **[azure.fr.md](azure.fr.md)** | [aws.fr.md](aws.fr.md) |
| Modèle | [`azure.bicep`](azure.bicep) | [`aws.cfn.yaml`](aws.cfn.yaml) |
| Machines | 3 × `Standard_B2s` (2 CPU, 4 Go), Debian 12 | 3 × `t3.medium` (2 CPU, 4 Go), Debian 12 |
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
ou dollars par jour pour les trois (vérifiez le prix dans votre portail : il varie selon la région). Créez un budget avec
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

Le test lui-même (`site.sh`) tourne, en CI, sur un seul hôte qui simule les trois machines. **Ces deux modèles n'ont pas
été exécutés par nous sur un vrai compte Azure ou AWS** au moment où nous écrivons : chaque guide commence par une
commande de *validation* qui vérifie le modèle sans rien créer. Si une étape d'ici ne correspond pas à votre portail
(les noms bougent), dites-le nous dans une [issue dev-test](../README.fr.md#nous-dire-ce-que-vous-avez-trouvé).

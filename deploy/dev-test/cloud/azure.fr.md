# Le test de site sur Azure, pas à pas

_English version: [azure.md](azure.md). Fait partie du [guide cloud](README.fr.md)._

> **Pas pour la production.** Lisez d'abord [README.fr.md](README.fr.md) (ce que vous obtenez, ce qui est ouvert, la clé
> ssh). Ici : de votre compte Azure à trois machines auxquelles vous pouvez vous connecter en ssh. Vous continuez ensuite
> dans [README.fr.md](README.fr.md#ensuite-quand-les-trois-machines-existent).

Il vous faut : un abonnement Azure avec des crédits, votre adresse publique, et la clé ssh du README. Environ 30 minutes
la première fois, surtout à attendre Azure.

## 1. Avant les machines

**Vérifiez les crédits.** Portail ([portal.azure.com](https://portal.azure.com)) → cherchez **Cost Management + Billing**
(Gestion des coûts + facturation) → **Crédits** (ou *Modes de paiement* / *Profil de facturation* selon votre offre) : le
solde et **la date d'expiration**. Vérifiez aussi que votre abonnement est celui qui les porte (en haut à droite,
*Abonnements*).

**Créez un budget avec une alerte.** Cherchez **Budgets** → **Ajouter** : étendue = votre abonnement, montant = 100,
alertes à 50 %, 80 % et 100 % vers votre e-mail. Il n'arrête rien : il vous prévient.

**Choisissez une région d'Europe**, par exemple **France Centre** (`francecentral`) ou **Europe Ouest** (`westeurope`).
Les abonnements obtenus par un programme n'autorisent parfois que certaines régions ou tailles : l'étape suivante vous le
dit.

## 2. Ouvrir Cloud Shell

Dans le portail, cliquez sur l'icône **`>_`** de la barre du haut → **Bash**. La première fois, Azure propose de créer un
petit compte de stockage pour lui : acceptez (cela coûte presque rien et utilise les crédits). Cloud Shell est un terminal
dans votre navigateur avec `az` et `git` déjà là ; ce n'est *pas* d'ici que vous ferez le ssh (le pare-feu ne laisse
entrer que votre propre adresse).

```bash
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git
cd TBP-NETWORK/deploy/dev-test/cloud
```

## 3. Vérifier que la taille existe dans votre région

```bash
az vm list-skus --location francecentral --size Standard_B2s --query "[].{taille:name, restreint:restrictions[0].reasonCode}" -o table
```

Une ligne dont la colonne *restreint* est vide, c'est bon. `NotAvailableForSubscription` veut dire que cette taille n'est
pas offerte à votre abonnement dans cette région : prenez une autre région (`westeurope`), ou une autre taille (ajoutez
`vmSize=Standard_B2ms` aux paramètres ci-dessous).

## 4. Créer les machines

Mettez votre adresse publique et votre clé **publique** (la ligne affichée par `cat "$HOME/.ssh/tbp-devtest.pub"` sur votre
ordinateur) là où c'est indiqué :

```bash
az group create --name tbp-devtest --location francecentral

# 1. valider : vérifie le modèle et ne crée rien
az deployment group validate --resource-group tbp-devtest --template-file azure.bicep \
  --parameters adminIp=<VOTRE ADRESSE> sshPublicKey='<LA LIGNE ENTIÈRE ssh-ed25519 AAAA… tbp-devtest>'

# 2. créer (3 à 5 minutes)
az deployment group create --resource-group tbp-devtest --template-file azure.bicep \
  --parameters adminIp=<VOTRE ADRESSE> sshPublicKey='<LA LIGNE ENTIÈRE ssh-ed25519 AAAA… tbp-devtest>' \
  --query properties.outputs.machines.value -o table
```

Le tableau final liste, pour `m1`, `m2`, `m3`, l'adresse **privée** (`10.20.0.10`, `.11`, `.12`) et l'adresse **publique** :
notez les trois publiques. Pour le revoir : `az deployment group show --resource-group tbp-devtest --name azure --query properties.outputs.machines.value -o table`.

Si *valider* ou *créer* échoue, le message nomme la cause. Les plus fréquentes :

| Message | Cause |
|---|---|
| `SkuNotAvailable`, `NotAvailableForSubscription` | taille ou région non offerte : étape 3 |
| `QuotaExceeded`, `Operation could not be completed as it results in exceeding approved … cores quota` | les abonnements neufs démarrent avec peu de cœurs : demandez-en plus dans *Quotas*, ou prenez une autre région |
| `RequestDisallowedByPolicy` | votre abonnement interdit cette région ou cette taille : prenez-en une autre |
| `InvalidParameter … publicKeys` | la clé est coupée ou contient un retour à la ligne : collez la ligne unique, entre apostrophes |

## 5. Se connecter

Depuis **votre ordinateur** (pas Cloud Shell), avec la première adresse publique :

```
ssh -i "$HOME/.ssh/tbp-devtest" tbp@<ADRESSE PUBLIQUE DE M1>
```

La première fois, `ssh` demande s'il faut faire confiance à la machine : répondez `yes`. Si ça marche, `exit` et
continuez dans **[README.fr.md — quand les trois machines existent](README.fr.md#ensuite-quand-les-trois-machines-existent)**,
avec `<login>` = `tbp` et `--env "azure, Standard_B2s, francecentral"`.

## 6. Votre adresse a changé

Portail → **Groupes de sécurité réseau** → `tbp-devtest-nsg` → **Règles de sécurité de trafic entrant** →
`allow-ssh-from-admin` → changez *Adresses IP sources* (`<adresse>/32`), enregistrez. Ou relancez l'étape 4 (*créer*) avec
la nouvelle adresse : elle ne change que la règle.

## 7. Mettre en pause, reprendre, supprimer

**Pause** (arrête la facturation du calcul ; les disques et les adresses coûtent encore un peu) :

```bash
az vm deallocate --ids $(az vm list --resource-group tbp-devtest --query "[].id" -o tsv)
```

Utilisez **deallocate** : `az vm stop` et le `shutdown` de la machine elle-même la laissent **facturée**. **Reprise** :
`az vm start --ids $(az vm list --resource-group tbp-devtest --query "[].id" -o tsv)`, puis `up` de nouveau sur M1 et M2
([README.fr.md](README.fr.md#quand-quelque-chose-ne-marche-pas)).

**Tout supprimer** (machines, disques, adresses, réseau, pare-feu), quand vous avez fini :

```bash
az group delete --name tbp-devtest --yes --no-wait
```

Supprimez ensuite votre copie de `m2.pack.tgz` et `m3.pack.tgz` si vous l'avez encore. Le budget et ses alertes restent :
ils ne coûtent rien.

## Ce que fait le modèle, et ce qu'il ne fait pas

Il crée : un réseau `10.20.0.0/24`, un pare-feu, trois machines Debian 12 (`Standard_B2s`, disque de 30 Go) avec des
adresses privées et publiques fixes. Il n'y installe **rien** : les paquets, OPA et Go sont installés par les commandes de
[site.fr.md](../site.fr.md#déployer), pour que ce que vous testez soit ce que `site.fr.md` documente. Le pare-feu autorise
ssh depuis votre adresse et, entre les trois machines, 8443, 9000 et 9100 ; **une règle à part refuse tout le reste**, y
compris ce qu'Azure autorise par défaut entre machines d'un même réseau. Les machines peuvent joindre Internet (pour
installer les paquets et cloner le dépôt). Pas de connexion par mot de passe, pas d'identité, pas de disque
supplémentaire.

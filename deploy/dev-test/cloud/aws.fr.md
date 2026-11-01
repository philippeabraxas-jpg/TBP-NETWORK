# Le test de site sur AWS, pas à pas

_English version: [aws.md](aws.md). Fait partie du [guide cloud](README.fr.md)._

> **Pas pour la production.** Lisez d'abord [README.fr.md](README.fr.md) (ce que vous obtenez, ce qui est ouvert, la clé
> ssh). Ici : de votre compte AWS à trois machines auxquelles vous pouvez vous connecter en ssh. Vous continuez ensuite
> dans [README.fr.md](README.fr.md#ensuite-quand-les-trois-machines-existent).

Il vous faut : un compte AWS avec des crédits, votre adresse publique, et la clé ssh du README. Environ 30 minutes la
première fois, surtout à attendre AWS.

## 1. Avant les machines

**Protégez le compte.** Connectez-vous à la console ([console.aws.amazon.com](https://console.aws.amazon.com)). L'adresse
e-mail avec laquelle vous vous êtes inscrit est l'utilisateur *racine* : activez son authentification multifacteur (en haut
à droite, votre nom → **Informations d'identification de sécurité** → **Attribuer un appareil MFA**) et, dès que vous
pouvez, travaillez avec un utilisateur administrateur distinct (**IAM Identity Center** ou **IAM → Utilisateurs**) plutôt
qu'avec la racine.

**Vérifiez les crédits.** Cherchez **Billing and Cost Management** (Facturation et gestion des coûts) → **Crédits** : le
solde et **la date d'expiration**.

**Créez un budget avec une alerte.** Même page → **Budgets** → **Créer un budget** → *Budget de coûts mensuel*, 100 USD,
alertes à 50 %, 80 % et 100 % vers votre e-mail. Il n'arrête rien : il vous prévient.

**Choisissez une région d'Europe** dans le sélecteur en haut à droite, par exemple **Europe (Paris) `eu-west-3`** ou
**Europe (Irlande) `eu-west-1`**, et **gardez la même pour toutes les étapes qui suivent** : une paire de clés, une pile et
des machines vivent dans une seule région.

## 2. Donner votre clé publique à AWS

**EC2** → menu de gauche **Paires de clés** → **Actions** → **Importer une paire de clés** : nom `tbp-devtest`, et collez la
ligne entière affichée par `cat "$HOME/.ssh/tbp-devtest.pub"` sur votre ordinateur → **Importer**.

## 3. Ouvrir CloudShell

Cliquez sur l'icône **`>_`** de la barre du haut (vérifiez que la région affichée est toujours celle que vous avez
choisie). CloudShell est un terminal dans votre navigateur avec `aws` et `git` déjà là ; ce n'est *pas* d'ici que vous
ferez le ssh (le pare-feu ne laisse entrer que votre propre adresse).

```bash
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git
cd TBP-NETWORK/deploy/dev-test/cloud
aws ssm get-parameter --name /aws/service/debian/release/12/latest/amd64 --query Parameter.Value --output text
```

La dernière commande affiche un identifiant d'image (`ami-…`) : c'est le Debian 12 officiel de cette région. Si elle
affiche une erreur, cette région ne le publie pas : prenez-en une autre.

## 4. Créer les machines

```bash
# 1. valider : vérifie le modèle et ne crée rien
aws cloudformation validate-template --template-body file://aws.cfn.yaml

# 2. créer (3 à 5 minutes)
aws cloudformation deploy --stack-name tbp-devtest --template-file aws.cfn.yaml \
  --parameter-overrides AdminIp=<VOTRE ADRESSE> KeyName=tbp-devtest

# 3. les adresses
aws cloudformation describe-stacks --stack-name tbp-devtest --query "Stacks[0].Outputs[].[OutputKey,OutputValue]" --output table
```

Le tableau liste les adresses **publiques** de M1, M2, M3 : notez-les. Leurs adresses privées sont `10.20.0.10`, `.11`,
`.12`.

Si la pile échoue, **Console → CloudFormation → `tbp-devtest` → Événements** nomme la cause (CloudShell l'affiche aussi).
AWS retire ce qu'il avait commencé à créer, et laisse la pile vide. Les causes les plus fréquentes :

| Message | Cause |
|---|---|
| `VcpuLimitExceeded`, `You have requested more vCPU capacity than your current vCPU limit` | un compte neuf a un petit quota : Service Quotas → *Amazon EC2* → *Running On-Demand Standard instances* → demandez 8, ou prenez une autre région. Les trois machines demandent 6 vCPU |
| `OptInRequired`, `Marketplace` | acceptez une fois les conditions (gratuites) de l'image Debian 12 : ouvrez-la sur AWS Marketplace (cherchez « Debian 12 ») → **Continue to Subscribe** → **Accept Terms**, puis recréez |
| `The key pair 'tbp-devtest' does not exist` | la paire de clés est dans une autre région, ou porte un autre nom : étape 2 |
| `Unsupported … in the Availability Zone` pour `t3.medium` | ajoutez `InstanceType=t3a.medium` aux paramètres, ou prenez une autre région |

Après un échec, la pile vide (`ROLLBACK_COMPLETE`) doit être supprimée avant de pouvoir la recréer :
`aws cloudformation delete-stack --stack-name tbp-devtest`, puis recommencez l'étape 4.

## 5. Se connecter

Depuis **votre ordinateur** (pas CloudShell), avec la première adresse publique :

```
ssh -i "$HOME/.ssh/tbp-devtest" admin@<ADRESSE PUBLIQUE DE M1>
```

La première fois, `ssh` demande s'il faut faire confiance à la machine : répondez `yes`. Si ça marche, `exit` et
continuez dans **[README.fr.md — quand les trois machines existent](README.fr.md#ensuite-quand-les-trois-machines-existent)**,
avec `<login>` = `admin` et `--env "aws, t3.medium, eu-west-3"` (la région que vous avez choisie).

## 6. Votre adresse a changé

Relancez l'étape 4 (*deploy*) avec la nouvelle valeur de `AdminIp` : CloudFormation ne change que la règle du pare-feu.
(Ou console → **EC2 → Groupes de sécurité** → le groupe de la pile → **Modifier les règles entrantes** → la règle ssh.)

## 7. Mettre en pause, reprendre, supprimer

**Pause** : les machines s'arrêtent (la facturation du calcul s'arrête ; les disques et les adresses fixes coûtent encore
un peu).

```bash
aws ec2 stop-instances --instance-ids $(aws ec2 describe-instances \
  --filters Name=tag:purpose,Values=tbp-devtest Name=instance-state-name,Values=running \
  --query "Reservations[].Instances[].InstanceId" --output text)
```

**Reprise** : la même commande avec `start-instances` et `Values=stopped`, puis `up` de nouveau sur M1 et M2
([README.fr.md](README.fr.md#quand-quelque-chose-ne-marche-pas)). Les adresses publiques ne changent pas.

**Tout supprimer** (machines, disques, adresses, réseau, pare-feu), quand vous avez fini :

```bash
aws cloudformation delete-stack --stack-name tbp-devtest
```

Cela laisse la paire de clés `tbp-devtest` (gratuite) et le budget (gratuit) ; supprimez votre copie de `m2.pack.tgz` et
`m3.pack.tgz`.

## Ce que fait le modèle, et ce qu'il ne fait pas

Il crée : un réseau `10.20.0.0/24` avec une passerelle Internet, un pare-feu (groupe de sécurité), trois machines Debian 12
(`t3.medium`, disque chiffré de 30 Go) avec des adresses privées fixes et chacune une adresse publique fixe (Elastic IP).
Il n'y installe **rien** : les paquets, OPA et Go sont installés par les commandes de
[site.fr.md](../site.fr.md#déployer), pour que ce que vous testez soit ce que `site.fr.md` documente. Le pare-feu autorise
ssh depuis votre adresse et, entre les trois machines, 8443, 9000 et 9100 ; tout le reste est refusé. Les machines
peuvent joindre Internet (pour installer les paquets et cloner le dépôt). Pas de connexion par mot de passe, pas de rôle
d'instance, pas de disque supplémentaire.

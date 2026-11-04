# The site test on Azure, step by step

_Version française : [azure.fr.md](azure.fr.md). Part of [the cloud guide](README.md)._

> **Not for production.** Read [README.md](README.md) first (what you get, what is open, the ssh key). Here: from your
> Azure account to three machines you can ssh to. Then you continue in [README.md](README.md#then-once-the-three-machines-exist).

You need: an Azure subscription with credits, your public address, and the ssh key of the README. About 30 minutes the
first time, most of it waiting for Azure.

## 1. Before the machines

**Check the credits.** Portal ([portal.azure.com](https://portal.azure.com)) → search **Cost Management + Billing** →
**Credits** (or *Payment methods* / *Billing profile* depending on your offer): the balance and **the expiry date**.
Check also that your subscription is the one carrying them (top right, *Subscriptions*).

**Create a budget with an alert.** Search **Budgets** → **Add**: scope = your subscription, amount = 100, alerts at 50 %,
80 % and 100 % to your e-mail. It does not stop anything: it warns you.

**Choose a region in Europe**, for example **France Central** (`francecentral`) or **West Europe** (`westeurope`).
Subscriptions obtained through a programme sometimes allow only some regions or sizes: the next step tells you.

## 2. Open Cloud Shell

In the portal, click the **`>_`** icon in the top bar → **Bash**. The first time, Azure offers to create a small storage
account for it: accept (it costs almost nothing and uses the credits). Cloud Shell is a terminal in your browser with `az`
and `git` already there; it is *not* where you will ssh from (the firewall only lets in your own address).

```bash
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git
cd TBP-NETWORK/deploy/dev-test/cloud
```

## 3. Check that the size exists in your region

```bash
az vm list-skus --location francecentral --size Standard_B2s --query "[].{size:name, restricted:restrictions[0].reasonCode}" -o table
```

A line with an empty *restricted* column is good. `NotAvailableForSubscription` means this size is not offered to your
subscription in this region: take another region (`westeurope`), or another size (add `vmSize=Standard_B2ms` to the
parameters below).

## 4. Create the machines

Put your public address and your **public** key (the line printed by `cat "$HOME/.ssh/tbp-devtest.pub"` on your computer)
where shown:

```bash
az group create --name tbp-devtest --location francecentral

# 1. validate: checks the template and creates nothing
az deployment group validate --resource-group tbp-devtest --template-file azure.bicep \
  --parameters adminIp=<YOUR ADDRESS> sshPublicKey='<THE WHOLE LINE ssh-ed25519 AAAA… tbp-devtest>'

# 2. create (3 to 5 minutes)
az deployment group create --resource-group tbp-devtest --template-file azure.bicep \
  --parameters adminIp=<YOUR ADDRESS> sshPublicKey='<THE WHOLE LINE ssh-ed25519 AAAA… tbp-devtest>' \
  --query properties.outputs.machines.value -o table
```

The table at the end lists, for `m1`, `m2`, `m3`, the **private** address (`10.20.0.10`, `.11`, `.12`) and the **public**
address: write the three public ones down. To see it again: `az deployment group show --resource-group tbp-devtest --name azure --query properties.outputs.machines.value -o table`.

If *validate* or *create* fails, the message names the cause. The usual ones:

| Message | Cause |
|---|---|
| `SkuNotAvailable`, `NotAvailableForSubscription` | size or region not offered to you: step 3 |
| `QuotaExceeded`, `Operation could not be completed as it results in exceeding approved … cores quota` | new subscriptions start with few cores: ask for more under *Quotas*, or take another region |
| `RequestDisallowedByPolicy` | your subscription forbids this region or size: take another |
| `InvalidParameter … publicKeys` | the key was cut or contains a line break: paste the one line, between single quotes |

## 5. Connect

From **your computer** (not Cloud Shell), with the first public address:

```
ssh -i "$HOME/.ssh/tbp-devtest" tbp@<M1 PUBLIC ADDRESS>
```

The first time, `ssh` asks whether to trust the machine: answer `yes`. If it works, `exit` and continue in
**[README.md — once the three machines exist](README.md#then-once-the-three-machines-exist)**, with `<login>` = `tbp`
and `--env "azure, Standard_B2s, francecentral"`.

## 6. Your address changed

Portal → **Network security groups** → `tbp-devtest-nsg` → **Inbound security rules** → `allow-ssh-from-admin` → change
*Source IP addresses* (`<address>/32`), save. Or run step 4's *create* again with the new address: it only changes the rule.

## 7. Pause, resume, delete

**Pause** (stops the compute charge; the disks and the addresses keep costing a little):

```bash
az vm deallocate --ids $(az vm list --resource-group tbp-devtest --query "[].id" -o tsv)
```

Use **deallocate**: `az vm stop` and the guest's own `shutdown` leave the machines **billed**. **Resume**:
`az vm start --ids $(az vm list --resource-group tbp-devtest --query "[].id" -o tsv)`, then `up` again on M1 and M2
([README.md](README.md#when-something-does-not-work)).

**Delete everything** (machines, disks, addresses, network, firewall), when you have finished:

```bash
az group delete --name tbp-devtest --yes --no-wait
```

Then delete your copy of `m2.pack.tgz` and `m3.pack.tgz` if you still have them. The budget and the budget alerts stay:
they cost nothing.

## What the template does and does not do

It creates: a network `10.20.0.0/24`, a firewall, three Debian 12 machines (`Standard_B2s`, 30 GB disk) with fixed private
and public addresses. It installs **nothing** on them: the packages, OPA and Go are installed by the commands of
[site.md](../site.md#deploy), so that what you test is what `site.md` documents. The firewall allows ssh from your address
and, between the three machines, 8443, 9000 and 9100; **a rule of its own refuses everything else**, including what Azure
allows by default between machines of one network. The machines can reach the Internet (to install packages and clone the
repository). No password login, no identity, no extra disk.

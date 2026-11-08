# The site test on AWS, step by step

_Version française : [aws.fr.md](aws.fr.md). Part of [the cloud guide](README.md)._

> **Not for production.** Read [README.md](README.md) first (what you get, what is open, the ssh key). Here: from your AWS
> account to three machines you can ssh to. Then you continue in [README.md](README.md#then-once-the-three-machines-exist).

You need: an AWS account with credits, your public address, and the ssh key of the README. About 30 minutes the first
time, most of it waiting for AWS.

## 1. Before the machines

**Protect the account.** Sign in to the console ([console.aws.amazon.com](https://console.aws.amazon.com)). The e-mail
address you registered with is the *root* user: turn on its multi-factor authentication (top right, your name →
**Security credentials** → **Assign MFA device**) and, as soon as you can, work with a separate administrator user
(**IAM Identity Center** or **IAM → Users**) instead of the root user.

**Check the credits.** Search **Billing and Cost Management** → **Credits**: the balance and **the expiry date**.

**Create a budget with an alert.** Same page → **Budgets** → **Create budget** → *Monthly cost budget*, 100 USD, alerts at
50 %, 80 % and 100 % to your e-mail. It does not stop anything: it warns you.

**Choose a region in Europe** in the selector at the top right, for example **Europe (Paris) `eu-west-3`** or **Europe
(Ireland) `eu-west-1`**, and **keep the same one for every step below**: a key pair, a stack and machines live in one
region.

## 2. Give AWS your public key

**EC2** → left menu **Key Pairs** → **Actions** → **Import key pair**: name `tbp-devtest`, and paste the whole line printed
by `cat "$HOME/.ssh/tbp-devtest.pub"` on your computer → **Import key pair**.

## 3. Open CloudShell

Click the **`>_`** icon in the top bar (check that the region shown is still the one you chose). CloudShell is a terminal in
your browser with `aws` and `git` already there; it is *not* where you will ssh from (the firewall only lets in your own
address).

```bash
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git
cd TBP-NETWORK/deploy/dev-test/cloud
aws ssm get-parameter --name /aws/service/debian/release/12/latest/amd64 --query Parameter.Value --output text
```

The last command prints an image identifier (`ami-…`): it is the official Debian 12 of this region. If it prints an error,
this region does not publish it: take another.

## 4. Create the machines

```bash
# 1. validate: checks the template and creates nothing
aws cloudformation validate-template --template-body file://aws.cfn.yaml

# 2. create (3 to 5 minutes)
aws cloudformation deploy --stack-name tbp-devtest --template-file aws.cfn.yaml \
  --parameter-overrides AdminIp=<YOUR ADDRESS> KeyName=tbp-devtest

# 3. the addresses
aws cloudformation describe-stacks --stack-name tbp-devtest --query "Stacks[0].Outputs[].[OutputKey,OutputValue]" --output table
```

The table lists the **public** addresses of M1, M2, M3: write them down. Their private addresses are `10.20.0.10`, `.11`,
`.12`.

If the stack fails, **Console → CloudFormation → `tbp-devtest` → Events** names the cause (CloudShell prints it too).
AWS removes what it had started to create, and leaves the empty stack. The usual causes:

| Message | Cause |
|---|---|
| `VcpuLimitExceeded`, `You have requested more vCPU capacity than your current vCPU limit` | a new account has a small quota: Service Quotas → *Amazon EC2* → *Running On-Demand Standard instances* → request 8, or take another region. The three machines need 6 vCPUs |
| `OptInRequired`, `Marketplace` | accept the (free) terms of the Debian 12 image once: open it on AWS Marketplace (search "Debian 12") → **Continue to Subscribe** → **Accept Terms**, then create again |
| `The key pair 'tbp-devtest' does not exist` | the key pair is in another region, or has another name: step 2 |
| `Unsupported … in the Availability Zone` for `m6i.large` | add `InstanceType=m5.large` to the parameters (same 2 CPUs and 8 GB, older generation), or take another region |

After a failure the empty stack (`ROLLBACK_COMPLETE`) must be deleted before you can create it again:
`aws cloudformation delete-stack --stack-name tbp-devtest`, then retry step 4.

## 5. Connect

From **your computer** (not CloudShell), with the first public address:

```
ssh -i "$HOME/.ssh/tbp-devtest" admin@<M1 PUBLIC ADDRESS>
```

The first time, `ssh` asks whether to trust the machine: answer `yes`. If it works, `exit` and continue in
**[README.md — once the three machines exist](README.md#then-once-the-three-machines-exist)**, with `<login>` = `admin`
and `--env "aws, m6i.large, eu-west-3"` (the region you chose).

## 6. Your address changed

Run step 4's *deploy* again with the new `AdminIp`: CloudFormation only changes the firewall rule. (Or console → **EC2 →
Security Groups** → the group of the stack → **Edit inbound rules** → the ssh rule.)

## 7. Pause, resume, delete

**Pause**: the machines stop (the compute charge stops; the disks and the fixed addresses keep costing a little).

```bash
aws ec2 stop-instances --instance-ids $(aws ec2 describe-instances \
  --filters Name=tag:purpose,Values=tbp-devtest Name=instance-state-name,Values=running \
  --query "Reservations[].Instances[].InstanceId" --output text)
```

**Resume**: the same command with `start-instances` and `Values=stopped`, then `up` again on M1 and M2
([README.md](README.md#when-something-does-not-work)). The public addresses do not change.

**Delete everything** (machines, disks, addresses, network, firewall), when you have finished:

```bash
aws cloudformation delete-stack --stack-name tbp-devtest
```

It leaves the key pair `tbp-devtest` (free) and the budget (free); delete your copy of `m2.pack.tgz` and `m3.pack.tgz`.

## What the template does and does not do

It creates: a network `10.20.0.0/24` with an Internet gateway, a firewall (security group), three Debian 12 machines
(`m6i.large`: 2 CPUs, 8 GB; 30 GB encrypted disk) with fixed private addresses and a fixed public address each (Elastic IP). It
installs **nothing** on them: the packages, OPA and Go are installed by the commands of [site.md](../site.md#deploy), so
that what you test is what `site.md` documents. The firewall allows ssh from your address and, between the three
machines, 8443, 9000 and 9100; everything else is refused. The machines can reach the Internet (to install packages and
clone the repository). No password login, no instance role, no extra disk.

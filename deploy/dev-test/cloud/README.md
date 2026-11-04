# deploy/dev-test/cloud — the three machines of the site test, in a cloud, step by step

_Version française : [README.fr.md](README.fr.md). Part of [deploy/dev-test](../README.md)._

> **Not for production.** Three throw-away machines, no real data. Everything here is deleted by deleting one
> group (Azure) or one stack (AWS). The templates open **one** thing to the Internet — ssh, from the **one** address you
> give — and nothing else.

[site.md](../site.md) says what the three machines are for and what to test. This folder gets you the three machines in a
cloud **without knowing the cloud**: a template creates the network, the firewall and the machines; you then follow
`site.md`.

| | Azure | AWS |
|---|---|---|
| Guide | **[azure.md](azure.md)** | [aws.md](aws.md) |
| Template | [`azure.bicep`](azure.bicep) | [`aws.cfn.yaml`](aws.cfn.yaml) |
| Machines | 3 × `Standard_B2s` (2 CPUs, 4 GB), Debian 12 | 3 × `t3.medium` (2 CPUs, 4 GB), Debian 12 |
| Login on the machines | `tbp` | `admin` |
| Delete everything | `az group delete` | `aws cloudformation delete-stack` |

Pick the one you have credits on. The test is the same on both: only the first part (creating the machines) differs, and
the label you give at `init` (`--env`) tells us which cloud your report comes from.

## What you get

```
 your computer ──ssh (22, from your address only)──► the three public addresses
 (and the console, through an ssh tunnel)

 private network 10.20.0.0/24
   M1  10.20.0.10   the cell            :8443 (agents, mutual TLS)   :9100 (live console)
   M2  10.20.0.11   application server  :9000 (the application)
   M3  10.20.0.12   the agent           —
```

| Flow | Port | Allowed |
|---|---|---|
| your computer → each machine | 22/tcp | from **your address** only |
| the machines → M1 | 8443/tcp, 9100/tcp | between the three machines only |
| the machines → M2 | 9000/tcp | between the three machines only |
| anything else, from the Internet or between the machines | — | refused |

Two consequences you will notice. **The live console is not open to the Internet**: you reach it through an ssh tunnel
(below), which also keeps its key off the network in clear. And **the packs travel through your computer**, not from
machine to machine, because the machines cannot ssh to each other (the packs hold the test's private keys: you delete
your copy afterwards).

## Before you create anything

**1. Your public address.** The address the Internet sees you at: search "what is my IP" in a browser. It looks like
`203.0.113.7`. If you change network (home, office, phone), it changes: redeploy or edit the rule (each guide says how).

**2. An ssh key**, on your computer. In *PowerShell* (Windows 10/11) or a terminal (macOS, Linux):

```
ssh-keygen -t ed25519 -f "$HOME/.ssh/tbp-devtest" -C tbp-devtest
cat "$HOME/.ssh/tbp-devtest.pub"
```

Give it a passphrase. The second command prints **one line** starting with `ssh-ed25519`: that is the *public* key, the
one the cloud needs. The file without `.pub` is private: it never leaves your computer. If `.ssh` does not exist,
create it first (`mkdir "$HOME/.ssh"`).

**3. A cost alert.** Credits end, and machines cost while they run. About 3 to 4 euros or dollars a day for the three
(check the price in your portal: it varies by region). Create a budget with an e-mail alert before the first machine
([azure.md](azure.md#1-before-the-machines), [aws.md](aws.md#1-before-the-machines)) and **stop or delete the machines when you do not test**.

## Then, once the three machines exist

Both guides end here. `<M1pub>`, `<M2pub>`, `<M3pub>` are the **public** addresses printed when the template finished;
`<login>` is `tbp` (Azure) or `admin` (AWS); `<key>` is `"$HOME/.ssh/tbp-devtest"`. Inside the test, the machines use
their **private** addresses `10.20.0.10`, `.11`, `.12`, never the public ones.

**1. M1 — the cell.** `ssh -i <key> <login>@<M1pub>`, then the M1 block of
[site.md](../site.md#deploy) with `<M1>` = `10.20.0.10` (the packages, OPA, Go, the clone), and:

```bash
scripts/devtest/site.sh m1 init --address 10.20.0.10 --env "<cloud>, <size>, <region>"     # e.g. "azure, Standard_B2s, francecentral"
scripts/devtest/site.sh m1 up
```

Stop before the two `scp` lines of `site.md`: they do not work here. Do this instead, **from your computer** (a second
terminal):

```
scp -i <key> <login>@<M1pub>:tbp-site-m1/packs/m2.pack.tgz .
scp -i <key> <login>@<M1pub>:tbp-site-m1/packs/m3.pack.tgz .
scp -i <key> m2.pack.tgz <login>@<M2pub>:
scp -i <key> m3.pack.tgz <login>@<M3pub>:
```

then delete the two files from your computer (`rm m2.pack.tgz m3.pack.tgz`; `Remove-Item` in PowerShell): `m3.pack.tgz`
holds the test agents' private keys.

**2. M2.** `ssh -i <key> <login>@<M2pub>`, then the M2 block of `site.md` with `<M2>` = `10.20.0.11`.

**3. M3.** `ssh -i <key> <login>@<M3pub>`, then the M3 block with `--app http://10.20.0.11:9000`. `site.sh m3 check` must end
with `site M3: the plumbing works`.

**4. The live console, in your browser.** `m1 up` printed an address like
`http://10.20.0.10:9100/?key=…`: it is a *private* address. Open a tunnel from your computer, in a terminal you leave open:

```
ssh -i <key> -N -L 9100:10.20.0.10:9100 <login>@<M1pub>
```

and open, in the browser, the same address with **`localhost`** in place of `10.20.0.10`:
`http://localhost:9100/?key=…`. [console.md](../console.md) says how to read the page. (Do not open port 9100 to the
Internet: it is plain HTTP.)

**5. Test.** Follow the table "What to test" of [site.md](../site.md#what-to-test-does-it-work), then "Attack it", then
`report` on each machine ([Telling us what you found](../site.md#telling-us-what-you-found)): the label you gave at `init`
says it was this cloud.

## When something does not work

| Symptom | Cause and cure |
|---|---|
| `Permission denied (publickey)` | wrong login (`tbp` on Azure, `admin` on AWS), wrong key file, or a public key pasted with a line break or cut. Compare `cat "$HOME/.ssh/tbp-devtest.pub"` with what you gave |
| `ssh` hangs, then `timed out` | your address is not the one you gave (it changed), or the machine is stopped. Check the address, and the machine's state in the portal |
| `m3 check` cannot reach the cell or the application | the firewall did not come with the template (you created the machines by hand?), or M1/M2 are not `up`. `site.sh m1 listeners` shows what listens |
| the console page does not open | the tunnel is not running (it needs its terminal open), or you used the private address instead of `localhost` |
| after you stopped and started the machines, nothing answers | the test's processes do not restart by themselves: run `up` again on M1 and M2 (a restart of `pepd` comes back in *refused* by design, see [site.md](../site.md)). Stopping and starting cloud machines is **not** something we have tested: if `up` fails, delete and redeploy |

## What was and was not checked

The test itself (`site.sh`) is run, in CI, on one host simulating the three machines. **These two templates have not been
run against a real Azure or AWS account by us** at the time of writing: each guide begins with a *validate* command that
checks the template without creating anything. If a step here does not match your portal (names move), tell us in a
[dev-test issue](../README.md#telling-us-what-you-found).

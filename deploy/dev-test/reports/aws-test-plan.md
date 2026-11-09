# AWS test plan, after the Azure run

_Version française : [aws-test-plan.fr.md](aws-test-plan.fr.md). Part of [deploy/dev-test](../README.md). The Azure run it follows: [2026-11-08-azure.md](2026-11-08-azure.md)._

> **A plan, not a result.** Nothing below has been run on AWS. The commands of parts 5 and 8 were written from the code, not
> run by their author; if one does not do what is said, that is a finding, write it down. What is marked "to learn" is an
> open question, not an expectation: do not read it as a claim.

The aim: the same test as on Azure (so the numbers can be compared), then the measures that Azure left open, with the
timings written down. Machines: [aws.md](../cloud/aws.md) (3 × `m6i.large`, 2 CPUs and 8 GB, like the `Standard_D2s_v5` of
the Azure run; a burstable size such as `t3` would make a comparison harder: its CPU depends on credits).

Where a command runs is in the first column: **PC** (your computer), **M1**, **M2**, **M3** (the machines, in
`~/TBP-NETWORK`). Write each result in the table at the end as you go.

## 1. Deploy, with timings

| Where | Command | Write down |
|---|---|---|
| PC | the steps 1 to 5 of [aws.md](../cloud/aws.md), with `time` before the `aws cloudformation deploy` line | the time the stack took; the region; the size |
| M1 | `init` as in [README.md](../cloud/README.md), with `--env "aws, m6i.large, <region>"`, with `time` before it | the time of `init` on a **cold** machine (nothing downloaded before) |
| M2, M3 | their `init`, with `time` | the times |
| M1, M2 | `scripts/devtest/site.sh m1 up`, `… m2 up`, with `time` | the times |

`site.sh m1 report` repeats the `init` and `up` times (and the commit, kernel, CPUs): keep the three reports.

## 2. The steps 1 to 14 of site.md

Do the table of [site.md](../site.md#what-to-test-does-it-work) as it is, on the console, and note in the results table whether each step
gives the same answer as on Azure (the Azure column of [the report](2026-11-08-azure.md#what-was-done)). The tokens and
approvals paragraph tells you the pace: a token lives 30 to 60 seconds.

## 3. The cell's decision and the application's verdict

On M3:

```bash
cd ~/TBP-NETWORK && scripts/devtest/site.sh m3 report
```

Compare with the Azure report: cell decision for a request refused for want of a plan (Azure: p50 553.5 ms, spread 3 ms),
`/healthz` of the application, the network between M3 and the cell. On M2, `site.sh m2 report`: the verdict of `pepd` on a
malformed token (Azure: 7.7 ms). For a **valid** token (Azure: about 260 ms, against about 7 ms for a refusal), read the
console after step 3 and again after step 11, five times if you can (approve, `act`, repeat).

To learn: does the 550 ms of the cell, and the 260 ms of a valid verdict, appear on AWS with the same values? If yes, they
do not come from the cloud.

## 4. OPA alone

On M1:

```bash
cd ~/TBP-NETWORK && export PATH=/usr/local/go/bin:$PATH && go run ./tests/opa_latency -transport unix -concurrency 1,4 -out ~/opa-latency.json
```

Keep the end of the output (Azure: 0 `opa-timeout` in 4,000 requests of one flow; 3.3 % at 4 at once).

## 5. Parallel decisions

On M3, one subject (`agent-i`), 48 refusals per round, as on Azure:

```bash
cd ~/TBP-NETWORK
for P in 1 2 3 4 16; do echo "== at once: $P"; time (seq 48 | xargs -P $P -I{} scripts/devtest/site.sh m3 act agent-i read doc-1 2>&1 | grep -o '"reason":"[a-z-]*"' | sort | uniq -c); done
```

Azure: 36.3 s, 20.5 s, 12.3 s, 9.8 s, 8.3 s, and `opa-overloaded` 0, 0, 1, 13, 42 of 48. Note the time and the count of each
reason for each line. On M1, `grep -c opa-timeout ~/tbp-site-m1/log/brokerd.log` before and after the series.

**Optional, with the cell's places raised to 4** (back up the file first; this restarts the cell, so redo the steps that need a
fresh state):

```bash
# M1
cd ~/TBP-NETWORK && scripts/devtest/site.sh m1 down && cp ~/tbp-site-m1/m1.env ~/m1.env.bak && echo 'TBP_OPA_MAX_INFLIGHT=4' >> ~/tbp-site-m1/m1.env && scripts/devtest/site.sh m1 up
# M3: the same loop with  for P in 4 16
# M1, to restore
scripts/devtest/site.sh m1 down && cp ~/m1.env.bak ~/tbp-site-m1/m1.env && scripts/devtest/site.sh m1 up && grep -c MAX_INFLIGHT ~/tbp-site-m1/m1.env
```

The last command must print `0`.

## 6. The write that follows a verdict (optional, M2 and M3)

`pepd` answers when its audit leaf is *accepted*, then the signed log catches up in the background; a cut inside the one-second
window denies. This part asks what a hard stop leaves behind. To learn: does the journal ever hold a record that the log does
not, after a `kill -9`?

On **M2**, run this and leave it waiting (it kills `pepd` as soon as one more record is written to its journal):

```bash
cd ~/tbp-site-m2 && n=$(wc -l < audit/pepd-records.jsonl) && while [ "$(wc -l < audit/pepd-records.jsonl)" -le "$n" ]; do :; done; kill -9 "$(cat run/pepd.pid)"; echo killed
```

On **M1**, approve a plan (`site.sh m1 sign agent-i read doc-5`), on **M3** run the `act` line it prints. Then on M2:

```bash
cd ~/TBP-NETWORK && scripts/devtest/site.sh m2 up        # it comes back "refused": reopen it as in steps 9-10 if you want to go on
~/tbp-site-m2/bin/tbp-audit verify -records ~/tbp-site-m2/audit/pepd-records.jsonl -key ~/tbp-site-m2/pepd-audit.key \
  -log ~/tbp-site-m2/registry/pepd -vkey-file ~/tbp-site-m2/registry/pepd/cell_log.vkey; echo "exit $?"
```

Write the whole output. Exit 0 means every record has its leaf and every leaf its record; 1 means a record without a leaf
(or the reverse) is named. Either is a result. Repeat two or three times: the window is short.

## 7. Files (the attacks of site.md)

The table "On M2 — someone who can write the server's files" and the line on M1 of [site.md](../site.md#attack-it): `site.sh m2 down`,
make the change, `m2 up`, note the message, restore the file. The Azure run did not do them.

## 8. Many invalid requests (last: it can leave `pepd` cut)

An empty token is refused by the application. A **non-empty invalid** one reaches `pepd`, which records a verdict for it. This
asks what a flood does to `pepd`'s journal and log. Do it last, and expect to restart `pepd`.

On M3:

```bash
URL=$(cat ~/tbp-site-m3/state/app-url)
time (seq 2000 | xargs -P 8 -I{} curl -s -o /dev/null -w '%{http_code}\n' -H 'X-TBP-Token: AAAA' "$URL/read/doc-1" | sort | uniq -c)
```

On M2, right after:

```bash
cd ~/tbp-site-m2 && grep -c ALARME log/pepd.log; grep ALARME log/pepd.log | tail -3
wc -l audit/pepd-records.jsonl; du -sh audit registry
~/TBP-NETWORK/scripts/devtest/site.sh m2 status
```

Then, from M1 and M3, get one **valid** token (as in steps 2–3) and present it. Write whether it is executed, refused, and
with what reason. To learn: does a flood of invalid requests make later valid ones fail (the `leaf-write-failed` cut)? That
would be a denial of service by design of "no leaf, no answer"; whether it is acceptable is a decision for the maintainers,
not for this plan.

## 9. Delete everything

`aws cloudformation delete-stack --stack-name tbp-devtest` ([aws.md](../cloud/aws.md#7-pause-resume-delete)), your copies of
the packs, and the proofs on your computer. Check in the console (EC2, Elastic IPs) that nothing is left that costs.

## Results

| # | Measure | Azure (2026-11-08) | AWS |
|---|---|---|---|
| 1 | stack creation | (template run once) | |
| 1 | `init` M1 / M2 / M3, cold | 19 s / 1 s / 0 s (warm Go cache) | |
| 1 | `up` M1 / M2 | 3 s / 3 s | |
| 2 | steps 1–14: same answers? | see the report | |
| 3 | cell decision, refused, p50 / p95 | 553.5 / 555.1 ms | |
| 3 | `pepd` verdict, malformed token, p50 | 7.7 ms | |
| 3 | `pepd` verdict, valid token | 255–272 ms | |
| 3 | class I / class W accepted by the cell | about 780 ms / 1.04 s | |
| 4 | OPA alone: `opa-timeout` in 4,000 / at 4 at once | 0 / 3.3 % | |
| 5 | 48 refusals at 1, 2, 3, 4, 16 at once: time | 36.3, 20.5, 12.3, 9.8, 8.3 s | |
| 5 | `opa-overloaded` | 0, 0, 1, 13, 42 | |
| 5 | with 4 places, at 4 and 16 | 0, 32 | |
| 5 | `opa-timeout` in `brokerd.log` | 1 in the first 67 | |
| 6 | `tbp-audit verify` after `kill -9` | 3 orphans in 3 stops at delay 0 (one by accident), none at 0.3 s (9 Nov) | |
| 7 | file attacks | M2: 5 of 5 refused; M1: 8 of 8 refused, 1 unmeasured setting accepted (9 Nov) | |
| 8 | flood of invalid requests: time, `ALARME` count, later valid request | 22,000 requests checked, no alarm, no loss; 6,000 more during a valid request, not checked afterwards (9 Nov) | |

Paste the three `report`s and this table into a **Dev-test feedback** issue (title starts with `[dev-test]`). Anything that is
exploitable goes privately, as [SECURITY.md](../../../SECURITY.md) says.

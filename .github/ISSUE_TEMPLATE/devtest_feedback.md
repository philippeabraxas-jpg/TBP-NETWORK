---
name: Dev-test feedback
about: You ran the DEV-TEST (deploy/dev-test) — a step that failed, a doc that is wrong, a behaviour that differs from what is written, your numbers
title: "[dev-test] "
---

> **Is it exploitable?** A way past a refusal, a silent acceptance, a leaked secret: do **not** post it here.
> Report it privately, as [SECURITY.md](../../SECURITY.md) says. Everything else is welcome below.

**What you ran**: the site (three machines, `deploy/dev-test/site.md`) or solo (one machine, `deploy/dev-test/solo.md`)?

**Your environment** (the same label you gave `--env`; provider, machine sizes, region, and whether the three
machines share one private network):

**What you tried** (the exact commands, in order, and on which machine):

**What you expected** (what the page or another guide says):

**What happened** (the output; the log lines from `~/tbp-site-m*/log/` or `~/tbp-devtest/log/` if something did not start):

**Where it got hard** (a step you were stuck on, a doc that was unclear, how long each part took):

**Output of `report`** on each machine you used (`scripts/devtest/site.sh m1|m2|m3 report`, or
`scripts/devtest/devtest.sh report`). They hold no key, seed, path, address or host name — check before you paste:

```
M1:

M2:

M3:
```

# pyrrho

[![CI](https://github.com/MarckMorris/pyrrho/actions/workflows/ci.yml/badge.svg)](https://github.com/MarckMorris/pyrrho/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A Terraform plan reviewer that compares the change, not the result.**

It reads the JSON form of a `terraform plan` and answers three questions before
anyone approves it: what this change really does, what it newly exposes, and
what an identity can do afterwards that it could not before. Findings come with
the values they were derived from, a SARIF file for GitHub's Security tab, and
an exit code your pipeline can act on.

No runtime dependencies. Python 3.10+. One command.

---

## The idea, in two changes

Every other Terraform scanner evaluates the **planned end state** against a
catalogue of policies. pyrrho compares the planned state against the **prior**
state. That one difference decides what each tool can see.

**A change that is not yours.** A security group has allowed SSH from the world
for two years. Your pull request edits a tag.

| | |
|---|---|
| A conventional scanner | *"SSH open to 0.0.0.0/0"* — true, and not caused by this change. By the third pull request the team has learned to ignore the tool |
| pyrrho | Silent. Nothing about the exposure changed |

**A change nobody can see.** Your pull request destroys a production database.

| | |
|---|---|
| A conventional scanner | Reads the end state. The database is not in it. There is nothing left to have an opinion about. Silent |
| pyrrho | `RD001` critical — *this destroys the relational database and its data* |

That is the whole design. The other 34 rules apply the same comparison to
routing, security group references, IAM policies, backups and audit trails.

Measured on the same corpus, against Checkov 3.3.10:

```
  pyrrho   detected 45/46 dangerous (98%)   false alarms 1/8 controls
  checkov  detected 28/46 dangerous (61%)   false alarms 4/8 controls
```

Those numbers need reading carefully, and
[Measured against Checkov](#measured-against-checkov) does that — the two tools
are complements, and Checkov is right on its own terms every time.

---

## What is not here

Release 0.2.1 ships **three analyzers**, for Terraform plan JSON, for AWS.
Stated up front so a clean run is not mistaken for a clean bill of health:

- **`blast-radius` and `compliance-drift` are not implemented.** They are named
  in the design and do not exist yet.
- **AWS only.** The resource tables are AWS, with a few GCP and Azure entries in
  `real-diff`. Nothing here is provider-agnostic.
- **Kubernetes manifests and CloudFormation are not read.** Plan JSON only.
- **No corpus case has been captured from a live `terraform plan`.** The parser
  *is* validated against 36 plan documents Terraform itself produced — see
  [What is verified, and how](#what-is-verified-and-how) — but the cases that
  drive the benchmark are written to the documented format, not captured.

A clean pyrrho run means "these three analyzers found nothing", not "this change
is safe". The tool says so in its own output.

---

## What it looks like

```
$ pyrrho plan.json

pyrrho reviewed 1 changing resource(s) in plan.json
  terraform 1.9.8  plan sha256 62add71d10e1  analyzers: network-exposure, real-diff

! CRITICAL NE001  Administrative or data service opened to the internet
  resource  aws_security_group.bastion
            This rule exposes SSH to any address on the internet. These services
            authenticate weakly or not at all at the network layer and are scanned
            continuously.
  evidence
            {
              "description": "SSH from the office",
              "new_sources": ["0.0.0.0/0 (the entire internet)"],
              "ports": "tcp/22 [SSH]",
              "previously_allowed": ["203.0.113.0/24"],
              "services_exposed": {"22": "SSH"}
            }
  fix
            Source the rule from the security group of the client tier, or from the
            VPN/bastion prefix list. For database ports there is no case for an
            internet-facing rule.

BLOCK  1 critical  threshold: high
$ echo $?
1
```

---

## Measured against Checkov

The corpus exists to be run against other tools, not just this one. Checkov is
the most widely deployed Terraform scanner and it reads plan files, so it is the
fair comparison.

```bash
pip install checkov && python scripts/compare_checkov.py
```

```
  pyrrho   detected 45/46 dangerous (98%)   false alarms 1/8 controls
  checkov  detected 28/46 dangerous (61%)   false alarms 4/8 controls
```

**Read that fairly, because the framing does a lot of work.** Checkov is not
trying to do delta analysis; its false alarms are failures against *pyrrho's*
definition of the job, not against its own. On its own terms — "does this end
state violate a policy" — Checkov is right every time. It has hundreds of
policies pyrrho will never have, and it covers Kubernetes, CloudFormation, Helm
and more.

What the numbers do show is that the two tools answer different questions, and
that the question pyrrho asks is not otherwise being asked:

| Corpus case | pyrrho | Checkov | Why |
|---|---|---|---|
| `nc002` tag edit on a group already open to the world | quiet | `CKV_AWS_24` | Checkov evaluates the end state, so pre-existing exposure is reported on a change that did not cause it |
| `nc003` SSH range narrowed from `0.0.0.0/0` to `10.20.0.0/16` | quiet | `CKV_AWS_23` | An improvement, reported as a problem |
| `rd001` production database destroyed | `RD001` critical | — | A destroyed resource is absent from the end state, so there is nothing left to evaluate |
| `rd011` CloudTrail destroyed | `RD009` high | — | Same shape: after the apply there is no trail resource to have an opinion about |
| `rd012` backup retention set to zero | `RD010` high | — | A valid end state. The harm is the transition |
| `ne021` network ACL deny entry deleted | `NE016` high | — | Removing a deny leaves nothing behind to object to |
| `pe005` MFA condition removed from a policy | `PE005` high | — | The statement grants the same actions before and after; only the guard rail is gone |
| `ne004` source range widened `/24` → `/8` | `NE001` high | — | Both states contain a CIDR; only the comparison shows the problem |
| `ne014` internet split into `0.0.0.0/1` + `128.0.0.0/1` | `NE002` critical | `CKV_AWS_24` | Both catch it, for different reasons |
| `ne019` rule sourced from a group that is itself open | `NE014` high | — | The reference reads as scoped; following it is what shows otherwise |

The `rd001` / `rd011` / `ne021` rows are the structural point. A scanner that
reads the planned end state **cannot** see a destroy, because the thing that
matters is the resource that is no longer there.

One honest mark against pyrrho in that run: it reports a `low` note on `nc001`,
a deliberately public HTTPS rule, which is counted as a false alarm here with no
exemption Checkov does not also get. It also misses `rd007`, because `--claim`
has no Checkov equivalent and is withheld to keep the comparison like for like.

**These tools are complements, not substitutes.** Run Checkov for policy
coverage. Run pyrrho for what this change does.

---

---

## Install

```bash
pip install -e .
```

No runtime dependencies. Python 3.10+.

---

## Use

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
pyrrho plan.json
```

| Flag | Effect |
|---|---|
| `--format json` | Machine-readable report on stdout, diagnostics on stderr |
| `--analyzer NAME` | Run one analyzer. Repeatable |
| `--fail-on SEVERITY` | Exit 1 at or above this level. Default `high` |
| `--claim PATTERN` | What the change is declared to touch (fnmatch). Anything else is reported |
| `--sarif PATH` | Write SARIF 2.1.0 for GitHub code scanning |
| `--sarif-location PATH` | Anchor alerts to a source file instead of the plan |
| `--baseline PATH` | Suppress findings recorded in a baseline |
| `--init-baseline PATH` | Record current findings and exit 0 |
| `--attest PATH` | Write a signed record of what was reviewed |

**Exit codes.** `0` reviewed and clean · `1` blocked at or above the threshold ·
`2` could not review. The distinction between 1 and 2 matters: a pipeline that
treats "the plan file was malformed" as "the plan is fine" is worse than no
pipeline.

### In CI

```yaml
- name: Review the plan
  run: |
    terraform show -json tfplan.binary > plan.json
    pyrrho plan.json --sarif pyrrho.sarif --fail-on high

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: pyrrho.sarif
```

### Adopting on an estate that already has problems

```bash
pyrrho plan.json --init-baseline pyrrho-baseline.json   # accept today's findings
pyrrho plan.json --baseline pyrrho-baseline.json        # block only on new ones
```

Baselined findings stay visible in the report and in the SARIF file, marked as
suppressed. They stop affecting the exit code; they do not disappear. The
baseline records the rule, the resource and the aspect in readable form, so it
can be reviewed as a list of accepted risks rather than a list of hashes.

### The attestation

```bash
PYRRHO_ATTEST_KEY=$CI_SECRET pyrrho plan.json --attest review.json
```

Writes a record binding the verdict to the SHA-256 of the exact plan reviewed,
the analyzers that ran, the threshold, and the tool version — signed with
HMAC-SHA256. Without the key it still writes the record and marks it
`"signed": false` with the reason, rather than implying an integrity guarantee it
cannot make.

A CI log line saying "security review passed" is not evidence. This is.

---

---

## Use it in a pull request

The repository is also a GitHub Action.

```yaml
- name: Review the plan
  uses: MarckMorris/pyrrho@v0.2.1
  with:
    plan: plan.json
    fail-on: high
    claim: "module.network.*,aws_security_group.*"
    sarif-location: infra/network.tf
```

It installs pyrrho, reviews the plan, writes the verdict to the workflow's job
summary, posts it as a pull request comment — updating the same comment on each
push rather than adding one per commit — and fails the job when the verdict is
`block`. Outputs are `verdict`, `findings`, `worst-severity` and `markdown`.

The comment leads with the verdict and a one-line reason, puts the findings in a
table, and folds the evidence into a `<details>` block. A review comment that
opens with three screens of JSON is a review comment nobody reads.

For the comment you need `pull-requests: write`; for the Security tab upload,
`security-events: write`.

---

---

## Rules

**`real-diff` — what the plan actually does**

| | |
|---|---|
| `RD001` | Stateful resource destroyed |
| `RD002` | Stateful resource replaced, destroying its data |
| `RD003` | Replacement destroys before creating, so traffic stops |
| `RD004` | Deletion protection or final-snapshot safety net removed |
| `RD005` | Plan computed against a drifted state |
| `RD006` | Sensitive value changes without showing what changed |
| `RD007` | Plan touches resources outside the declared scope |
| `RD008` | Security-relevant attribute unknown until apply |
| `RD009` | Audit or logging trail removed |
| `RD010` | Recoverability weakened |

**`network-exposure` — what the plan makes reachable**

| | |
|---|---|
| `NE001` | Administrative or data service opened to a public network |
| `NE002` | Every port opened to the entire internet |
| `NE003` | New internet-facing ingress rule |
| `NE004` | Ingress source widened |
| `NE005` | S3 public access guard disabled or removed |
| `NE006` | Database or warehouse made publicly accessible |
| `NE007` | Load balancer changed from internal to internet-facing |
| `NE008` | Network ACL allows the internet, removing subnet segmentation |
| `NE009` | Unrestricted egress to the internet |
| `NE010` | Kubernetes API server reachable from the internet |
| `NE011` | Resource assigned a public IP address |
| `NE012` | Security group rules unknown until apply |
| `NE013` | Subnet becomes publicly routable |
| `NE014` | Ingress sourced from a security group that is itself open |
| `NE015` | Two network segments joined |
| `NE016` | Network ACL deny boundary removed |
| `NE017` | Resource policy grants access to any principal |
| `NE018` | Managed prefix list widened |

**`privilege-escalation` — what an identity can do that it could not before**

| | |
|---|---|
| `PE001` | Statement grants every action, or every action on every resource |
| `PE002` | `iam:PassRole` granted with an unrestricted target |
| `PE003` | Role trust policy accepts an unbounded principal |
| `PE004` | Privilege escalation primitive granted |
| `PE005` | Condition removed from an existing Allow statement |
| `PE006` | Allow statement written with `NotAction` or `NotResource` |
| `PE007` | Broad AWS-managed policy attached |
| `PE008` | IAM policy unknown until apply |

### Five things the rules do that string matching does not

**Containment, not equality.** `NE001` and `NE004` use real CIDR arithmetic.
Widening `198.51.100.0/24` to `198.0.0.0/8` is still "a CIDR" in the diff and
admits 65,536 times more addresses. Narrowing `0.0.0.0/0` to `10.20.0.0/16` is an
improvement and is not reported.

**The whole internet, however it is spelled.** `0.0.0.0/1` and `128.0.0.0/1`
cover the same space as `0.0.0.0/0`, and so do four `/2`s. `cidr.covers_internet`
collapses the set before judging it, so the reach is what it is rather than what
it looks like.

**Ranges, not ports.** `1024-65535` is one line in a diff. It contains Redis,
MongoDB, Elasticsearch and the kubelet. `NE001` enumerates every service a range
swallows, and an *unknown* range is reported as unreviewable rather than empty.

**Following the reference.** `NE014` resolves a rule sourced from `sg-abc123`
against the other groups in the plan. Referencing a group instead of a CIDR is
the advice everyone gives; it is only a restriction if the referenced group is
one.

**The IAM delta, statement by statement.** `PE005` pairs statements across
`before` and `after`, so a statement that kept its actions and lost its
`MultiFactorAuthPresent` condition is reported as a weakening. Nothing about the
resulting policy records that the condition was ever there.

---

---

## How the rules were found

The first release had twelve network rules and eight diff rules, all written by
reasoning about what could go wrong. Then an adversarial audit was run against
the analyzers with one instruction: *find changes this code would review and
report nothing about.* It returned twelve false negatives, each verified by
constructing the plan and watching pyrrho stay silent.

That audit is where most of this release came from. The worst of them:

| What it missed | Why the check failed | Now |
|---|---|---|
| `cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]` | Every world check tested one block for `prefixlen == 0`. Two halves are the whole internet and each half is an ordinary CIDR | `cidr.covers_internet` collapses the set first |
| A brand-new public source on a database port | The widening branch required a *prior* CIDR to exist, so a rule that had only security-group sources reported nothing when it gained a public `/24` | Severity now scales with reach, with no prior-value precondition |
| A world-open rule whose ports are unknown | `all([])` is `True`, so an unresolved port range was judged "web ports only" and reported `low` | An unknown range is `NE003` at `high`, and says it cannot be reviewed |
| `aws_default_security_group` | One word different from `aws_security_group`, and it applies to every ENI in the VPC with no explicit group | Both types share the extraction path |
| A network ACL `deny` entry deleted | The check read only `after`. After the change there is nothing there to object to | `NE016`, comparing both sides |
| CloudTrail destroyed | In none of the three lookup tables | `RD009` |
| `backup_retention_period` set to `0` | Not a guard attribute by name, and it deletes the backups already taken | `RD010` |

Two of those — the split internet and the unknown-port downgrade — are evasions
rather than oversights: a change written that way passes review *because* it
reads as scoped. Both now have corpus cases, so they stay caught.

---

---

## The corpus and the benchmark

Every number below is printed by `scripts/benchmark.py`. If a figure appears in
this README and that script does not produce it, the figure is a bug.

```bash
python scripts/generate_corpus.py && python scripts/benchmark.py --verbose
```

```
pyrrho benchmark
  corpus: 46 dangerous cases, 8 benign controls
  cases captured from a real terraform plan: 0/54

  detection    46/46 dangerous cases fully detected (100%)
  false alarms 0/54 cases (0%)
```

Test suite: **776 tests, 98% line coverage**, on Python 3.10, 3.11 and 3.12.

```bash
pytest -q --cov=pyrrho --cov-report=term-missing
```

### How to read the 100%

**It is close to meaningless as an absolute measure**, and it is stated here
rather than left for you to work out. The corpus and the rules were written by
the same person, so the rules detect the corpus by construction. What the number
is actually good for:

- **as a regression bar** — it must stay at 100%, and CI fails when it does not;
- **as a floor for comparison** — the corpus is the input for benchmarking *other*
  tools, and that comparison is the number that would mean something;
- **as a specification** — `corpus/manifest.json` states, per case, which rules
  must fire and which must not.

The **false-alarm figure is the more informative one**. The eight benign
controls are changes a naive checker gets wrong: HTTPS served to the public on
purpose, a tag edit on a group that was already open, a source range being
*narrowed*, a stateless resource being replaced, an IAM policy being tightened, a
correctly scoped cross-account trust with an `ExternalId`, a default route to a
NAT gateway, and a network ACL allow for the VPC range. A tool that flags those
is a tool that gets disabled in a month.

There is no random sampling anywhere, so there is no seed to fix. The corpus is a
fixed set of files and the analyzers are deterministic, which means two runs on
one commit are byte-identical — a property asserted by
`tests/test_corpus.py::TestBenchmark::test_the_benchmark_is_deterministic`.

---

## What is verified, and how

There are two separate questions, and conflating them is how a project ends up
overclaiming. They are answered by two different scripts.

### 1. Does the parser handle what Terraform really emits?

**Yes, and this is checked in CI.** HashiCorp's own repository contains the
golden files it uses to test `terraform show -json`. They were produced by
Terraform, they exist specifically to exercise the format's awkward corners, and
they span years of releases.

```bash
python scripts/validate_against_terraform.py
```

```
pyrrho parser vs. Terraform's own plan JSON golden files
  source: hashicorp/terraform @ 7d231820db94 (BUSL-1.1, not vendored)

  plan documents found  36
  parsed                36
  rejected              0
  analyzer crashes      0

  plan format versions  1.0, 1.1, 1.2
  terraform versions    0.13.0, 0.13.1-dev, 1.1.0-dev, 1.2.0-dev, 1.4.4, 1.5.0
  plan flavours         HCP Terraform redacted plan, terraform show -json
  action sets           create, delete, delete+create, no-op, update
  action reasons        delete_because_no_resource_config, replace_because_cannot_update

  findings on real plans:
    RD005      internal/cloud/testdata/plan-json-full/plan-redacted.json
    RD005      internal/command/testdata/show-json/drift/output.json
    RD005      internal/command/testdata/show-json/moved-drift/output.json
```

Two things worth reading twice. `RD005` fires on exactly the three documents that
contain drift and on nothing else — the analyzer found the right thing in real
data it had never seen. And the run surfaced a genuine gap: HCP Terraform
(formerly Terraform Cloud) serves its redacted plan under `plan_format_version`
rather than `format_version`, so every team using remote execution would have been
told their plan was unreadable. That is fixed, and it is the sort of thing only
real input finds.

These files are **not vendored**. hashicorp/terraform is BUSL-1.1, which an MIT
project cannot redistribute. The script fetches them at a pinned commit and reads
them in place.

### 2. Do the rules catch dangerous changes without crying wolf?

This is what the corpus and `scripts/benchmark.py` answer, and here the honesty
caveat still stands in full.

The plan JSON in `corpus/cases/*/plan.json` is **written to Terraform's documented
plan format, not captured from a live `terraform plan` against a real cloud
account.** The benchmark prints `cases captured from a real terraform plan: 0/54`
and `tests/test_corpus.py` fails if anyone flips that flag without updating this
section.

What that does and does not undermine, now that the parser is validated upstream:

- It does **not** mean the shapes are invented. Every action set the corpus uses
  appears in Terraform's own golden files, as printed above.
- It **does** mean the corpus is a test of the *rules*, written by the same person
  who wrote them, and cannot discover a dangerous pattern its author did not
  think of.

Every case ships the HCL it corresponds to, so it can be regenerated with
`scripts/regenerate_from_terraform.sh` by anyone with a Terraform binary and
credentials.

---

---

## Also works as a Claude Code plugin

Everything above is a Python CLI with no runtime dependencies and no connection
to any model. This section is an optional integration on top of it.

The repository doubles as a Claude Code plugin. Loaded, it provides:

- `/pyrrho:review` — a skill that drives the whole review
- two subagents, `network-exposure` and `real-diff`, that run the deterministic
  pass and then do the judgement work a rule cannot: resolving referenced
  security groups, tracing what consumes a resource about to be destroyed, and
  reconciling the plan against what the pull request claims
- `pyrrho` on `PATH`, working without a separate install

```bash
claude --plugin-dir /path/to/pyrrho
```

Both agents are declared with `tools: Bash, Read, Grep, Glob` — no `Edit` or
`Write`. The kit reviews; it does not change infrastructure. That constraint is
asserted by a test, not just documented.

Their instructions require them to keep two categories apart in every report:
findings pyrrho produced, with a rule ID and evidence, and concerns the agent
formed itself, marked unverified. The value of a second opinion collapses if you
cannot tell which half was mechanically checked.

**What is asserted about them, and what is not.** Tests check that the agent
files parse, that neither can edit or write files, that each names the analyzer
it drives, and that each is told not to invent findings. Nothing tests the
*quality* of the reviews they produce, because there is no honest way to. Treat
them as a convenience over the CLI, not as the thing that makes the findings
trustworthy — the CLI is that.

---

---

## Repository layout

```
pyrrho/
├── pyrrho/                     the package
│   ├── plan.py                 Terraform plan JSON reader
│   ├── cidr.py                 containment and widening arithmetic
│   ├── ports.py                port classification
│   ├── policy.py               IAM policy parsing and statement diffing
│   ├── core.py                 findings, report, verdict, analyzer registry
│   ├── analyzers/              the three analyzers
│   ├── sarif.py                SARIF 2.1.0
│   ├── baseline.py             incremental adoption
│   ├── attest.py               signed record of the review
│   └── cli.py                  command line
├── corpus/                     the specification and the benchmark input
│   ├── manifest.json           per case: which rules must fire, which must not
│   └── cases/<id>/{main.tf,plan.json}
├── action.yml                  the reusable GitHub Action
├── CONTRIBUTING.md             how to reproduce every number here, and add a rule
├── SECURITY.md                 what counts as a vulnerability in a review tool
├── CHANGELOG.md                what changed, and what the audit found
├── agents/                     Claude Code subagents
├── skills/review/SKILL.md      Claude Code skill
├── bin/pyrrho                  wrapper so the plugin works without an install
└── scripts/
    ├── generate_corpus.py             emits the corpus from one declaration per case
    ├── benchmark.py                   the detection and false-alarm numbers
    ├── validate_against_terraform.py  parses Terraform's own golden plan files
    ├── compare_checkov.py             the same corpus, scored against Checkov
    ├── self_review.py                 reviews the corpus, emits SARIF for CI
    └── regenerate_from_terraform.sh   recaptures the corpus from a real binary
```

CI runs the tests on three Python versions, regenerates the corpus and fails on
any diff, runs the benchmark, parses Terraform's own golden plan files, asserts
the documented exit codes, validates the plugin layout, and uploads the corpus
review to this repository's own Security tab. There is no `continue-on-error` in
the test job: a pipeline that stays green while its tests fail turns a real
signal into decoration.

---

---

## Next

1. Capture the corpus from a real `terraform plan` and flip
   `verified_against_terraform`. Less urgent than it was — the parser is
   validated against Terraform's own output — but it is the last honesty caveat
   left standing.
2. Extend the comparison beyond Checkov: Trivy and Terrascan next, same corpus,
   same scoring.
3. Resolve security-group-to-security-group references, so `NE001` can follow a
   rule sourced from another group.
4. Then, and only then, a third analyzer.

---

## Name

Pyrrho of Elis (c. 360–270 BC) founded the school that carries his name. Its
central practice is *epoché*: suspension of judgement while the evidence is
insufficient. Not "I don't know" — "I do not assert this yet."

That is the whole design brief.

---

## License

MIT.

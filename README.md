# pyrrho

**Adversarial review of Terraform plans.** It does not deploy. It doubts.

Point it at a `terraform plan` and it reports what the plan actually does and
what it newly exposes — with the evidence for every claim, a SARIF file for
GitHub's Security tab, and an exit code your pipeline can act on.

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

## What is not here

This is release 0.1.0 and it ships **two analyzers, for Terraform plans only**.
The following are named in the design and are **not implemented**:

| Not implemented | What it would do |
|---|---|
| `blast-radius` | Trace what else depends on a changed resource, and who loses access |
| `privilege-escalation` | Diff IAM policies and report the *delta*, not the whole policy |
| `compliance-drift` | Measure distance from a CIS baseline |

Also not covered, and worth knowing before you rely on it:

- **Kubernetes manifests and CloudFormation are not read.** Terraform plan JSON only.
- **Rules sourced from a security group ID or a prefix list are not resolved.**
  pyrrho reads CIDRs. If a rule says "allow from `sg-abc123`", pyrrho does not know
  what is in `sg-abc123`.
- **Routing is not analyzed.** A subnet moved to a public route table, a VPC peering
  connection, a transit gateway attachment — none of these are examined.
- **No corpus case has been captured from a live `terraform plan`.** See
  [Honesty about the corpus](#honesty-about-the-corpus).

A clean pyrrho run means "these two analyzers found nothing", not "this change is
safe". The tool says so in its own output.

---

## Why it exists

Plenty of tools scan Terraform. The distinguishing choice here is **delta
discipline**: pyrrho compares the planned state against the prior state and
reports only what *this change* does.

That sounds like a detail. It is the difference between a tool a team keeps and a
tool a team switches off. Run a conventional scanner against an estate that has
been running for five years and it returns hundreds of findings, none of which
the current pull request caused. The reviewer learns that the tool's output is
not about their change, and stops reading it.

So: a security group that already allowed SSH from the world before this plan is
not reported. The corpus contains a case that asserts exactly this
(`nc002-preexisting-exposure-left-untouched`) and the test suite fails if it ever
starts reporting.

The second choice is that **every finding carries the values it was derived
from**. `previously_allowed`, `new_sources`, `widening_factor`, `action_reason`.
You can check the claim without re-running the tool and without trusting it.

---

## Install

```bash
pip install -e .
```

No runtime dependencies. Python 3.10+.

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

## As a Claude Code plugin

The repository is also a plugin. Loaded, it provides:

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

**`network-exposure` — what the plan makes reachable**

| | |
|---|---|
| `NE001` | Administrative or data service opened to the internet |
| `NE002` | Every port opened to the entire internet |
| `NE003` | New internet-facing ingress rule |
| `NE004` | Ingress source widened |
| `NE005` | S3 public access guard disabled or removed |
| `NE006` | Database instance made publicly accessible |
| `NE007` | Load balancer changed from internal to internet-facing |
| `NE008` | Network ACL allows the internet, removing subnet segmentation |
| `NE009` | Unrestricted egress to the internet |
| `NE010` | Kubernetes API server reachable from the internet |
| `NE011` | Resource assigned a public IP address |
| `NE012` | Security group rules unknown until apply |

`NE012` is the one that tends to be missing elsewhere. When a rule set comes from
a module output Terraform cannot resolve at plan time, the honest output is *"this
cannot be reviewed before it exists"*. A scanner that reads only the `after` block
sees an empty ingress list and reports no findings, which reads identically to a
clean result.

### Three things the network rules get right that string matching does not

**Containment, not equality.** `NE004` uses real CIDR arithmetic. Widening
`198.51.100.0/24` to `198.0.0.0/8` is still "a CIDR" in the diff and admits 65,536
times more addresses. Narrowing `0.0.0.0/0` to `10.20.0.0/16` is an improvement and
is not reported.

**Ranges, not ports.** `1024-65535` is one line in a diff. It contains Redis,
MongoDB, Elasticsearch and the kubelet. `NE001` enumerates every service a range
swallows.

**All three provider shapes.** AWS expresses security group rules three different
ways — inline `ingress` blocks on `aws_security_group`, the legacy
`aws_security_group_rule`, and the current `aws_vpc_security_group_ingress_rule`
with entirely different attribute names (`cidr_ipv4`, `ip_protocol`). A checker
written against one shape silently reports nothing on the others.

---

## The corpus and the benchmark

Every number below is printed by `scripts/benchmark.py`. If a figure appears in
this README and that script does not produce it, the figure is a bug.

```bash
python scripts/generate_corpus.py && python scripts/benchmark.py --verbose
```

```
pyrrho benchmark
  corpus: 23 dangerous cases, 4 benign controls
  cases captured from a real terraform plan: 0/27

  detection    23/23 dangerous cases fully detected (100%)
  false alarms 0/27 cases (0%)
```

Test suite: **439 tests, 98% line coverage**, on Python 3.10, 3.11 and 3.12.

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

The **false-alarm figure is the more informative one**. The four benign controls
are changes a naive checker gets wrong: HTTPS served to the public on purpose,
a tag edit on a group that was already open, a source range being *narrowed*, and
a stateless resource being replaced. A tool that flags those is a tool that gets
disabled in a month.

There is no random sampling anywhere, so there is no seed to fix. The corpus is a
fixed set of files and the analyzers are deterministic, which means two runs on
one commit are byte-identical — a property asserted by
`tests/test_corpus.py::TestBenchmark::test_the_benchmark_is_deterministic`.

### Honesty about the corpus

The plan JSON in `corpus/cases/*/plan.json` is **written to Terraform's documented
plan format (`format_version` 1.2), not captured from a live `terraform plan`
against a real cloud account.** No case has been verified against a real
Terraform run: the benchmark prints `0/27` for this and
`tests/test_corpus.py` fails if anyone flips the flag without updating this
section.

What that does and does not undermine:

- It does **not** affect whether the parser handles real plans. The shapes it
  handles — `["delete","create"]` versus `["create","delete"]`, `after_unknown`
  markers, `before_sensitive` arriving as `false` rather than a dict — are the
  documented ones, and each has its own test.
- It **does** mean the corpus cannot catch a case where real Terraform emits
  something the documentation does not describe.

Every case ships the HCL it corresponds to, so it can be regenerated:
`scripts/regenerate_from_terraform.sh`. Closing this gap is the first item in
[Next](#next).

---

## Repository layout

```
pyrrho/
├── pyrrho/                     the package
│   ├── plan.py                 Terraform plan JSON reader
│   ├── cidr.py                 containment and widening arithmetic
│   ├── ports.py                port classification
│   ├── core.py                 findings, report, verdict, analyzer registry
│   ├── analyzers/              the two analyzers
│   ├── sarif.py                SARIF 2.1.0
│   ├── baseline.py             incremental adoption
│   ├── attest.py               signed record of the review
│   └── cli.py                  command line
├── corpus/                     the specification and the benchmark input
│   ├── manifest.json           per case: which rules must fire, which must not
│   └── cases/<id>/{main.tf,plan.json}
├── agents/                     Claude Code subagents
├── skills/review/SKILL.md      Claude Code skill
├── bin/pyrrho                  wrapper so the plugin works without an install
└── scripts/
    ├── generate_corpus.py      emits the corpus from one declaration per case
    ├── benchmark.py            the numbers in this README
    └── self_review.py          reviews the corpus, emits SARIF for CI
```

CI runs the tests on three Python versions, regenerates the corpus and fails on
any diff, runs the benchmark, asserts the documented exit codes, validates the
plugin layout, and uploads the corpus review to this repository's own Security
tab. There is no `continue-on-error` in the test job: a pipeline that stays green
while its tests fail turns a real signal into decoration.

---

## Next

1. Capture the corpus from a real `terraform plan` and flip
   `verified_against_terraform`. This is the largest open gap.
2. Benchmark other Terraform security tools against the same corpus. That
   comparison is the number worth publishing.
3. Resolve security-group-to-security-group references, so `NE001` can follow a
   rule sourced from another group.
4. Then, and only then, a third analyzer.

## Name

Pyrrho of Elis (c. 360–270 BC) founded the school that carries his name. Its
central practice is *epoché*: suspension of judgement while the evidence is
insufficient. Not "I don't know" — "I do not assert this yet."

That is the whole design brief.

## License

MIT.

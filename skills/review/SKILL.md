---
description: Review a Terraform plan adversarially before it is applied. Use when the user asks to review, check, audit or sanity-check a terraform plan, a pull request touching infrastructure, or a proposed change to security groups, IAM, storage or networking. Also use when another agent has produced infrastructure code and the user wants a second opinion on it.
---

# Review a Terraform plan

Establish what the plan really does and what it newly exposes, then give a
verdict with evidence. The posture is adversarial: the change is assumed to be
wrong until the plan says otherwise. That includes changes produced by another
agent, which is the case this skill exists for.

$ARGUMENTS may name a plan file, a directory, or nothing.

## 1. Get the plan JSON

pyrrho reads the JSON form of a plan, not HCL, because only the plan carries the
prior state that every judgement depends on.

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
```

If the user has already produced one, use it. If Terraform is not available and
no plan file exists, say so and stop rather than reviewing the HCL as a
substitute — you would be guessing at the "before" side of every diff.

## 2. Run the review

```bash
pyrrho plan.json
```

Useful flags:

| Flag | When to use it |
|---|---|
| `--format json` | You are going to reason over the findings programmatically |
| `--claim 'aws_security_group.*'` | The pull request says what it touches; check the plan agrees |
| `--fail-on critical` | The team is adopting gradually and only wants the worst blocked |
| `--baseline pyrrho-baseline.json` | An existing estate with known accepted findings |
| `--sarif pyrrho.sarif` | The result should land in GitHub's Security tab |
| `--attest pyrrho-attestation.json` | A record of the review is needed for audit |

Exit codes: `0` clean, `1` blocked at or above the threshold, `2` could not
review.

## 3. Go past the deterministic pass

pyrrho's rules are the floor. Delegate the judgement work to the two subagents,
which is what they are for:

- the **network-exposure** agent, for rules sourced from other security groups,
  routing and peering changes, and whether the stated reason matches the change;
- the **real-diff** agent, for what consumes a resource that is about to be
  destroyed, and whether the plan does more than the pull request claims.

Run both when the change touches networking and stateful resources. Run one when
it clearly touches only the other's domain.

## 4. Report

Verdict first, then findings ordered by severity. For each one: what changes,
why it matters, and the evidence read from the plan.

Keep two categories visibly apart:

- **Verified** — produced by pyrrho, with a rule ID and its evidence block.
- **Unverified** — your own concern, with what you would need to check.

Never merge them. The value of this review is that a reader can tell which
claims were checked mechanically and which are judgement.

## What this does not cover

Say this plainly in the report rather than letting silence imply coverage.
The current release ships two analyzers, for Terraform plans only:

- IAM privilege escalation is **not** analyzed.
- Blast radius across dependent resources is **not** analyzed.
- Compliance drift against a CIS baseline is **not** analyzed.
- Kubernetes manifests and CloudFormation are **not** read.
- Rules sourced from security group IDs and prefix lists are **not** resolved.

A clean pyrrho run means "the two analyzers found nothing", not "this change is
safe".

# Changelog

Every figure below is produced by a script in `scripts/`. Nothing here is
quoted from memory.

## 0.2.1

Both fixes below were found by CI failing on a Dependabot pull request, not by
anything I ran locally. That is the argument for the matrix.

### Fixed

- **The verdict depended on the Python version.**
  `ipaddress.ip_network("0.0.0.0/1").is_private` is `True` on Python 3.10 and
  `False` on 3.11 and later. `cidr.is_public` delegated to that property, so a
  security group rule admitting **half the internet** reported nothing at all on
  3.10 and `high` on 3.11. Reachability is now decided against an explicit list
  of the IANA special-purpose blocks and is identical on 3.10, 3.11, 3.12 and
  3.13, each asserted by a parametrised test.
- **The Action died on exactly the case it exists for.** pyrrho exits 1 whenever
  a review blocks. The step captured that exit code for the JSON render but had
  `set -e` back on for the markdown render, which then killed the step before
  any output was written. A correctly-blocking review looked like a broken
  action. `tests/test_action.py` now extracts the step's shell out of the YAML,
  substitutes the inputs and runs it, because 747 Python tests could not see a
  bug in a bash script embedded in a workflow file.
- The pull request comment no longer fails the job when it cannot be posted.
  Dependabot and fork pull requests run with a read-only token, and reporting a
  permissions problem as if it were a finding is worse than not commenting.

### Changed

- CI now tests Python 3.13 as well. The version-dependent bug existed on the
  oldest supported interpreter only; a narrower matrix would not have found it.

## 0.2.0

### The audit

An adversarial audit was run against the analyzers with one instruction: *find
changes this code reviews and reports nothing about.* It returned twelve false
negatives, each verified by constructing the plan and watching pyrrho stay
silent. Most of this release is the answer to it.

Two were evasions rather than oversights — a change written that way passes
review *because* it reads as scoped:

- `cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]` is the whole internet written as
  two ordinary-looking CIDRs. Every world check tested a single block for
  `prefixlen == 0`, so all-ports-from-anywhere produced no finding at all. Reach
  is now computed by collapsing the set (`cidr.covers_internet`).
- A world-open rule whose ports Terraform cannot resolve was reported `low` and
  described as "the standard web ports", because `all([])` is `True`. It is now
  `high` and says the exposure cannot be reviewed.

### Added

- **`privilege-escalation` analyzer** (`PE001`–`PE008`) over a new
  `pyrrho/policy.py`. Statements are paired across `before` and `after`, so a
  policy that kept its actions and lost its `MultiFactorAuthPresent` condition
  is reported as a weakening — the case an end-state checker structurally
  cannot see.
- **`NE013`** a subnet becomes publicly routable, with no security group change.
- **`NE014`** follows a rule sourced from another security group into whatever
  that group actually admits.
- **`NE015`** VPC peering, transit gateway attachments, and routes across them.
- **`NE016`** a network ACL deny boundary removed.
- **`NE017`** resource policies granting any principal.
- **`NE018`** a shared managed prefix list widened.
- **`RD009`** audit or logging trail removed.
- **`RD010`** recoverability weakened — `backup_retention_period` to zero,
  versioning suspended, retention shortened, point-in-time recovery disabled.
- **A GitHub Action.** One `uses:` line reviews a plan, writes the verdict to
  the job summary, posts it as a pull request comment that updates in place, and
  fails the job on `block`.
- **`--format markdown`** for that comment and for job summaries.
- `scripts/compare_checkov.py`, run in CI so the README's comparison cannot
  become a claim about a version of Checkov that shipped a year ago.

### Fixed

- HCP Terraform (formerly Terraform Cloud) serves its redacted plan under
  `plan_format_version` rather than `format_version`. Every team using remote
  execution was being told their plan was unreadable.
- The corpus left `planned_values` empty. Most scanners read that section and
  ignore `resource_changes`, so they saw zero resources and reported a clean
  result on a file they could not read. `corpus/README.md` claimed the corpus
  was tool-neutral; now it is.
- The widening branch required a *prior* CIDR to exist, so a rule whose sources
  were security-group references only reported nothing when it gained a
  hardcoded public `/24` on a database port.
- Type-table gaps: `aws_default_security_group`, `aws_default_network_acl`,
  `aws_s3_account_public_access_block`, `aws_redshift_cluster` (where
  `publicly_accessible` **defaults to true**), `aws_dms_replication_instance`,
  and the launch template's nested `network_interfaces` block.
- Protocol numbers (`"6"`) are now canonicalised against names (`"tcp"`), so a
  rule cannot dodge comparison by changing spelling.
- Two findings of the same rule on one resource no longer share a fingerprint.
  Baselining one accepted rule was silently suppressing a different one added to
  the same group later.

### Changed

- `NE001` severity now scales with reach — `critical` for internet-wide, `high`
  for a broad public block, `medium` for a specific public range — instead of
  requiring a literal `0.0.0.0/0`.
- A widening is folded into the finding it explains rather than emitted
  alongside it. `NE004` fires only when the growth is the whole story.
- The Claude Code plugin moved down the README. It is an optional integration
  over a dependency-free CLI, not the identity of the project.

### Numbers

| | 0.1.0 | 0.2.0 |
|---|---|---|
| Analyzers | 2 | 3 |
| Rules | 20 | 36 |
| Corpus | 23 dangerous, 4 controls | 46 dangerous, 8 controls |
| Detection | 23/23 | 46/46 |
| False alarms | 0/27 | 0/54 |
| Tests | 439 | 747 |
| Coverage | 98% | 98% |

Against Checkov 3.3.10, same corpus, same scoring: pyrrho 45/46 dangerous (98%)
with 1/8 controls noisy; Checkov 28/46 (61%) with 4/8 noisy. Read
[the caveats](README.md#measured-against-checkov) before quoting that.

## 0.1.1

- CI triggered on `main` only while the repository was created on `master`.
  Nothing errored, no run appeared, no badge turned red — CI was simply absent,
  and a workflow that never runs is indistinguishable from one that passes.
  `tests/test_ci.py` now parses the workflow and asserts that the branch the
  checkout is on is one it triggers for.
- `scripts/validate_against_terraform.py`: the parser reads 36 plan documents
  Terraform itself produced, at a pinned commit. 36/36 parsed, 0 rejected, 0
  crashes, across plan format versions 1.0/1.1/1.2 and Terraform 0.13 to 1.5.

## 0.1.0

First release. Two analyzers — `real-diff` and `network-exposure` — over
Terraform plan JSON, with SARIF output, CI exit codes, a baseline for
incremental adoption, and an HMAC-signed record of what was reviewed.

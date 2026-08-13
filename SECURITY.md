# Security policy

## Reporting a vulnerability

Report it privately through GitHub's
[security advisory form](https://github.com/MarckMorris/pyrrho/security/advisories/new).
Please do not open a public issue for anything exploitable.

Expect a first reply within a week. If you have not heard back in two, assume
the message was lost and open a public issue saying only that you sent a private
report — no detail.

## What counts as a vulnerability here

pyrrho reads a plan file and writes a report. It never contacts a cloud
provider, never applies anything, and has no runtime dependencies. That makes
the interesting attack surface narrow but not empty:

| | |
|---|---|
| **A crafted plan file that executes code, escapes the working directory or exhausts memory** | A vulnerability. The parser is fed untrusted JSON by design |
| **A crafted plan that makes pyrrho report a clean verdict on a dangerous change** | A vulnerability, and the one this project cares about most. See below |
| **A finding pyrrho does not have a rule for** | Not a vulnerability. Open an issue; it is a feature request with a good story |
| **The attestation HMAC** | `PYRRHO_ATTEST_KEY` is a shared secret. Anyone holding it can forge a record. That is the documented trust model, not a flaw |

## The evasion class specifically

A change written so that it passes review *because* it reads as scoped is the
failure mode this tool exists to prevent, so it is treated as a security bug
rather than a missing feature.

Two are already fixed and have corpus cases, which is the shape a report should
take:

- `cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]` — the whole internet as two
  ordinary-looking CIDRs. Every `prefixlen == 0` check let it through.
- A world-open rule whose ports Terraform cannot resolve, which was reported as
  `low` and described as "the standard web ports", because `all([])` is `True`.

If you have found a third, that is the most useful thing you can send.

## Supported versions

The latest release only. This is a single-maintainer project and backporting to
older tags would be a promise it cannot keep.

## What pyrrho does not promise

A clean run means the analyzers that ran found nothing in the change they were
given. It is not an assurance that a change is safe, and the tool says so in its
own output. Do not use a passing pyrrho run as the sole gate on a production
apply.

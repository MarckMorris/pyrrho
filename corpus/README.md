# The corpus

Twenty-three infrastructure changes that should never reach production, and four
that should pass without complaint.

This directory is the project's specification, its regression suite and its
benchmark input at the same time. A rule exists because a case here demands it;
`tests/test_corpus.py` fails if a rule fires that no case declares.

## Layout

```
manifest.json              every case, with what must fire and what must not
cases/<id>/main.tf         the Terraform an engineer would plausibly have written
cases/<id>/plan.json       the plan that HCL produces
```

Do not edit these files by hand. They are emitted by
`scripts/generate_corpus.py`, and CI regenerates them and fails on any diff.
Change the declaration in the generator instead.

## What a case declares

```json
{
  "id": "ne001-ssh-opened-to-the-internet",
  "title": "Bastion security group opened to 0.0.0.0/0 on SSH",
  "why": "The most common real incident. Someone is locked out, widens the rule ...",
  "analyzer": "network-exposure",
  "benign": false,
  "expect": ["NE001"],
  "forbid": ["NE002"],
  "claim": [],
  "max_severity": null,
  "verified_against_terraform": false
}
```

`expect` is the recall assertion: every rule listed must fire. `forbid` is the
precision assertion: none of these may fire. `why` has to explain how the change
happens in a real team — a case nobody would plausibly write teaches nothing.

## The four benign controls

These matter more than the dangerous cases. Detection is easy to add; not being
noise is what determines whether anyone leaves the tool switched on.

| Case | What it tests |
|---|---|
| `nc001-https-served-to-the-public-on-purpose` | 443 open to the world is a web server, not an incident |
| `nc002-preexisting-exposure-left-untouched` | A tag edit on an already-open group must report nothing |
| `nc003-source-range-narrowed` | The tool knows the *direction* of a change, not just that one happened |
| `nc004-stateless-resource-replaced` | Replacement only matters when something irreplaceable goes with it |

`nc002` is the single most important file in this directory. It is the delta
discipline the whole design rests on.

## Honesty about these files

**No case has been captured from a live `terraform plan`.** The JSON is written to
Terraform's documented plan format (`format_version` 1.2, `terraform_version`
1.9.8) from the declaration in the generator.

Every case ships its HCL, so anyone with a Terraform binary and credentials can
regenerate the JSON from a real plan:

```bash
./scripts/regenerate_from_terraform.sh
```

That script flips `verified_against_terraform` to `true` for each case it
regenerates. `tests/test_corpus.py` currently asserts every case is `false`, so
whoever does this will be told, by a failing test, that the README claim needs
updating too.

## Using the corpus against another tool

This is what the corpus is actually for. `manifest.json` is tool-neutral: it
states which dangerous changes are present and which changes are benign. Point
any Terraform scanner at `cases/*/plan.json` or `cases/*/main.tf`, score it the
same way `scripts/benchmark.py` scores pyrrho, and the comparison means
something in a way that pyrrho's own 100% does not.

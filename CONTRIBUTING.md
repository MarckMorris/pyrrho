# Contributing

The most valuable contribution is a **dangerous Terraform change this tool
reviews and says nothing about.** Everything else follows from that.

## Getting set up

```bash
git clone https://github.com/MarckMorris/pyrrho.git
cd pyrrho
pip install -e ".[dev]"
pytest -q
```

No services, no credentials, no Terraform binary. If `pytest` does not pass on a
fresh clone, that is a bug worth reporting on its own.

## Reproducing every number in the README

There is no figure in the README that a script here does not produce. If you
find one, delete it or open an issue.

```bash
python scripts/generate_corpus.py          # regenerate the corpus (idempotent)
python scripts/benchmark.py --verbose      # detection and false-alarm rates
python scripts/validate_against_terraform.py   # parse HashiCorp's own golden plans
pip install checkov && python scripts/compare_checkov.py   # the comparison
pytest -q --cov=pyrrho --cov-report=term-missing
```

`validate_against_terraform.py` clones a pinned commit of `hashicorp/terraform`
and reads its `terraform show -json` golden files in place. Those files are
BUSL-1.1 and are deliberately never vendored into this MIT repository.

## Adding a rule

In this order. The order is the point.

1. **Write the corpus case first**, in `scripts/generate_corpus.py`. It needs a
   realistic `tf` block, a `why` that explains how the change happens in a real
   team, the rule IDs it must `expect`, and the ones it must `forbid`.
2. Run `python scripts/generate_corpus.py` and confirm the case fails: the rule
   does not exist yet.
3. Write the rule. Give it an ID in the existing series (`NE`, `RD`, `PE`).
4. Every finding must carry `evidence` — the concrete values read from the plan —
   and a `remediation`. A test enforces both across the whole corpus.
5. **Add a benign control** if the rule could plausibly fire on a safe change.
   The eight existing controls matter more than the forty-six dangerous cases:
   detection is easy, staying quiet is not.

A rule with no corpus case is a rule nobody has ever seen fire, and
`tests/test_corpus.py` fails if one exists.

## The rule that shapes everything else

**Report the delta, never the state.** If the condition was already true before
this plan, it is not this change's doing and it does not get reported. There is
a test asserting exactly this on a security group that was already open to the
world (`nc002-preexisting-exposure-left-untouched`), and it is the single most
important test in the repository.

## What will get a pull request rejected

- A number in the README with no script that reproduces it.
- `continue-on-error` in the test job. A pipeline that stays green while its
  tests fail turns a real signal into decoration.
- A rule with no corpus case, or a corpus case edited by hand rather than
  through the generator. CI regenerates and fails on any diff.
- Anything that reports a pre-existing condition as a finding.
- Spanish, or any language other than English, anywhere in the repository.

## Reporting a false negative

Open an issue with the plan JSON, or the HCL and the two states. Say what you
expected and what pyrrho said. If it is genuinely dangerous and genuinely
missed, it becomes a corpus case with your name on the commit.

If it is an *evasion* — a change that passes review because it reads as scoped —
please report it privately first. See [SECURITY.md](SECURITY.md).

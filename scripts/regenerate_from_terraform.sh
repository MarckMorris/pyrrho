#!/usr/bin/env bash
# Regenerate each corpus case's plan.json from a real `terraform plan`.
#
# The committed plan.json files are written to Terraform's documented plan
# format rather than captured from a live run, because the machine that built
# this repository had no Terraform binary and no cloud credentials. That gap is
# stated in README.md and in corpus/README.md, and the benchmark prints it.
#
# This script closes it. Run it where you have:
#   * terraform >= 1.6 on PATH
#   * credentials for the provider each case uses (AWS today)
#
# It never applies anything. `terraform plan` against a real account reads state
# and provider schemas; it does not create resources. Even so, run it against an
# account you are willing to have read.
#
# Usage:
#   ./scripts/regenerate_from_terraform.sh              # every case
#   ./scripts/regenerate_from_terraform.sh ne001-ssh-opened-to-the-internet

set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cases_dir="$root/corpus/cases"
manifest="$root/corpus/manifest.json"

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform not found on PATH. Install it, or leave the corpus as it is:" >&2
  echo "  the committed plan.json files are schema-conformant, and README.md says so." >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found on PATH; it is needed to update the manifest." >&2
  exit 2
fi

selected=("$@")
if [ ${#selected[@]} -eq 0 ]; then
  mapfile -t selected < <(cd "$cases_dir" && ls -1)
fi

regenerated=()

for case_id in "${selected[@]}"; do
  case_dir="$cases_dir/$case_id"
  if [ ! -d "$case_dir" ]; then
    echo "skip $case_id: no such case" >&2
    continue
  fi

  echo "==> $case_id"
  workdir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$workdir'" EXIT

  cp "$case_dir/main.tf" "$workdir/main.tf"

  # Each case's HCL references variables and prior resources that only exist in
  # the scenario it describes. Supply them here, per case, as you work through
  # them; a case that cannot plan cleanly is reported and left alone rather than
  # committed half-regenerated.
  if [ -f "$case_dir/regenerate.tfvars" ]; then
    cp "$case_dir/regenerate.tfvars" "$workdir/terraform.tfvars"
  fi

  if ! (cd "$workdir" && terraform init -input=false -no-color >/dev/null); then
    echo "    terraform init failed; leaving $case_id as it is" >&2
    rm -rf "$workdir"; trap - EXIT; continue
  fi

  if ! (cd "$workdir" && terraform plan -input=false -no-color -out=tfplan.binary >/dev/null); then
    echo "    terraform plan failed; leaving $case_id as it is" >&2
    echo "    (most cases need a prior state to diff against; see corpus/README.md)" >&2
    rm -rf "$workdir"; trap - EXIT; continue
  fi

  (cd "$workdir" && terraform show -json tfplan.binary) > "$case_dir/plan.json"
  echo "    regenerated $case_dir/plan.json"
  regenerated+=("$case_id")

  rm -rf "$workdir"; trap - EXIT
done

if [ ${#regenerated[@]} -eq 0 ]; then
  echo "nothing regenerated."
  exit 0
fi

python3 - "$manifest" "${regenerated[@]}" <<'PY'
import json
import sys

manifest_path, *ids = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as fh:
    data = json.load(fh)

updated = set(ids)
for case in data["cases"]:
    if case["id"] in updated:
        case["verified_against_terraform"] = True

with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")

print(f"marked {len(updated)} case(s) verified_against_terraform")
PY

cat <<'EOF'

Two follow-ups, both of which a test will remind you about:

  1. tests/test_corpus.py asserts every case is verified_against_terraform=false.
     Update that test now that some are true.
  2. README.md states that no case has been captured from a live terraform run,
     and the benchmark prints 0/N. Update both.
EOF

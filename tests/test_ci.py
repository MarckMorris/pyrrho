"""The CI workflow is asserted, because a broken one fails silently.

This file exists because of a real incident. The workflow triggered on `main`
only; the repository was created on `master`. Nothing errored, no run appeared,
no badge turned red — CI was simply absent, and the first anyone would notice is
when a reviewer asks why there are no runs. A workflow that does not run is
indistinguishable from a workflow that passes, unless something checks.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def current_branch() -> str | None:
    if not (ROOT / ".git").exists():
        return None
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if result.returncode != 0:
        return None
    name = result.stdout.strip()
    return name if name and name != "HEAD" else None


def triggers(workflow: dict) -> dict:
    # PyYAML parses the bare key `on` as the boolean True. That is a real YAML
    # 1.1 rule, not a bug, and it catches everyone once.
    return workflow.get("on") or workflow.get(True) or {}


class TestItWillActuallyRun:
    def test_the_workflow_is_valid_yaml_with_jobs(self, workflow):
        assert isinstance(workflow, dict)
        assert workflow.get("jobs"), "the workflow defines no jobs"

    def test_it_triggers_on_push(self, workflow):
        assert "push" in triggers(workflow)

    def test_it_covers_both_common_default_branch_names(self, workflow):
        branches = set(triggers(workflow)["push"]["branches"])
        assert {"main", "master"} <= branches, (
            "list both default branch names; a workflow naming only one is inert "
            "on a repository that uses the other, and says nothing about it"
        )

    def test_this_checkout_branch_would_trigger_it(self, workflow):
        """The check that would have caught the original incident."""
        branch = current_branch()
        if branch is None:
            pytest.skip("not a git checkout")
        branches = set(triggers(workflow)["push"]["branches"])
        assert branch in branches, (
            f"this checkout is on '{branch}', which is not in the workflow's push "
            f"branches {sorted(branches)}. CI would never run here."
        )

    def test_it_can_be_triggered_by_hand(self, workflow):
        assert "workflow_dispatch" in triggers(workflow)


class TestTheJobsAreHonest:
    def test_no_job_hides_a_failure(self, workflow):
        """Rule from the project brief: no continue-on-error anywhere.

        A pipeline that stays green while its steps fail turns a real signal
        into decoration.
        """
        # One deliberate exception, asserted by name so it cannot spread: the
        # dogfood step runs the Action against a plan that is *meant* to block,
        # and the steps after it check that it blocked for the right reason. The
        # job still fails if those checks fail.
        allowed = {"action/Review a deliberately dangerous plan"}

        offenders: list[str] = []
        for job_name, job in workflow["jobs"].items():
            if job.get("continue-on-error"):
                offenders.append(job_name)
            for step in job.get("steps", []) or []:
                label = f"{job_name}/{step.get('name', 'unnamed step')}"
                if step.get("continue-on-error") and label not in allowed:
                    offenders.append(label)
        assert not offenders, f"continue-on-error found in: {offenders}"

    def test_the_dogfood_exception_still_asserts_the_outcome(self, workflow):
        steps = workflow["jobs"]["action"]["steps"]
        names = [s.get("name") for s in steps]
        assert "The Action must have blocked, and said why" in names
        check = next(s for s in steps if s.get("name") == "The Action must have blocked, and said why")
        assert "exit 1" in check["run"]

    def test_the_expected_jobs_are_present(self, workflow):
        expected = {
            "test",
            "corpus",
            "upstream-plans",
            "compare",
            "self-review",
            "cli-contract",
            "action",
            "plugin",
        }
        assert expected <= set(workflow["jobs"]), (
            f"missing jobs: {sorted(expected - set(workflow['jobs']))}"
        )

    def test_every_job_checks_out_the_repository(self, workflow):
        for name, job in workflow["jobs"].items():
            uses = [step.get("uses", "") for step in job.get("steps", []) or []]
            assert any(u.startswith("actions/checkout") for u in uses), name

    def test_only_the_publishing_job_may_write_security_events(self, workflow):
        for name, job in workflow["jobs"].items():
            perms = job.get("permissions") or {}
            if perms.get("security-events") == "write":
                assert name == "self-review", (
                    f"{name} requests security-events: write; only the job that "
                    f"uploads SARIF should have it"
                )

    def test_the_test_job_runs_on_three_python_versions(self, workflow):
        matrix = workflow["jobs"]["test"]["strategy"]["matrix"]["python"]
        assert {"3.10", "3.11", "3.12"} <= set(str(v) for v in matrix)

    def test_the_python_versions_match_what_the_package_claims(self, workflow):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        matrix = [str(v) for v in workflow["jobs"]["test"]["strategy"]["matrix"]["python"]]
        for version in matrix:
            assert f'Programming Language :: Python :: {version}' in pyproject, (
                f"CI tests {version} but pyproject.toml does not claim to support it"
            )

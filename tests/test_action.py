"""The composite Action is asserted like the workflow is.

An action.yml with a typo in an input name fails at the moment someone else
tries to use it, in their repository, with an error that points at their
workflow. These checks move that discovery here.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"


@pytest.fixture(scope="module")
def action() -> dict:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def raw() -> str:
    return ACTION.read_text(encoding="utf-8")


class TestShape:
    def test_it_is_a_composite_action(self, action):
        assert action["runs"]["using"] == "composite"

    def test_every_step_declares_a_shell_or_uses_an_action(self, action):
        for step in action["runs"]["steps"]:
            assert step.get("shell") or step.get("uses"), step.get("name")

    def test_only_the_pull_request_comment_may_fail_softly(self, action):
        """The exit code has to mean something, with one named exception.

        Dependabot and fork pull requests run with a read-only token, so posting
        a comment returns 403. By that point the review has already happened and
        its verdict is in the job summary; failing there would report a
        permissions problem as if it were a finding. Nothing else may do this.
        """
        allowed = {"Comment on the pull request"}
        offenders = [
            s.get("name")
            for s in action["runs"]["steps"]
            if s.get("continue-on-error") and s.get("name") not in allowed
        ]
        assert not offenders, offenders

    def test_the_last_step_re_raises_a_blocking_verdict(self, action):
        last = action["runs"]["steps"][-1]
        assert "verdict == 'block'" in last["if"]
        assert "exit 1" in last["run"]


class TestInputs:
    def test_the_plan_is_the_only_required_input(self, action):
        required = {name for name, spec in action["inputs"].items() if spec.get("required")}
        assert required == {"plan"}

    def test_every_input_is_documented(self, action):
        for name, spec in action["inputs"].items():
            assert len(spec.get("description", "").strip()) > 30, name

    def test_every_optional_input_has_a_default(self, action):
        for name, spec in action["inputs"].items():
            if not spec.get("required"):
                assert "default" in spec, name

    def test_the_default_threshold_matches_the_cli(self, action):
        from pyrrho.cli import build_parser

        cli_default = build_parser().get_default("fail_on")
        assert action["inputs"]["fail-on"]["default"] == cli_default

    def test_the_analyzer_names_in_the_docs_are_real(self, action):
        from pyrrho.core import available

        described = action["inputs"]["analyzers"]["description"]
        for name in available():
            assert name in described, f"{name} is not listed in the analyzers input"

    def test_every_input_is_actually_used(self, action, raw):
        for name in action["inputs"]:
            assert f"inputs.{name}" in raw, f"input '{name}' is declared and never read"


class TestOutputs:
    def test_every_output_maps_to_the_review_step(self, action):
        for name, spec in action["outputs"].items():
            assert "steps.review.outputs." in spec["value"], name

    def test_the_documented_outputs_are_the_ones_the_script_writes(self, action, raw):
        written = set(re.findall(r'print\(f?"(\w+)=', raw))
        referenced = {
            re.search(r"steps\.review\.outputs\.([\w-]+)", spec["value"]).group(1)
            for spec in action["outputs"].values()
        }
        # `worst-severity` is the output name; `worst` is the key written.
        assert written == {"verdict", "findings", "worst", "markdown"}
        assert referenced == {"verdict", "findings", "worst", "markdown"}


class TestPullRequestComment:
    def test_it_updates_one_comment_rather_than_adding_more(self, raw):
        assert "updateComment" in raw
        assert "<!-- pyrrho-review -->" in raw

    def test_it_only_comments_on_pull_requests(self, action):
        step = next(s for s in action["runs"]["steps"] if "Comment" in (s.get("name") or ""))
        assert "github.event_name == 'pull_request'" in step["if"]


class TestReadmeDocumentsIt:
    def test_the_readme_shows_how_to_use_the_action(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        assert "MarckMorris/pyrrho@" in readme, "the README must show the uses: line"


class TestTheReviewScriptActuallyRuns:
    """Execute the action's shell, because 747 Python tests could not see it.

    The review step is a bash script embedded in YAML. It shipped with a bug no
    Python test could reach: both renders return exit 1 when the review blocks,
    and only the first one had `set -e` disabled around it, so the second killed
    the step before any output was written. A correctly-blocking review looked
    like a broken action, and it only happened on the case the job exists for.
    """

    @staticmethod
    def review_script(action: dict, **inputs: str) -> str:
        step = next(s for s in action["runs"]["steps"] if s.get("id") == "review")
        script = step["run"]
        defaults = {
            name: str(spec.get("default", ""))
            for name, spec in action["inputs"].items()
        }
        defaults.update(inputs)
        for name, value in defaults.items():
            script = script.replace("${{ inputs.%s }}" % name, value)
        assert "${{" not in script, "an expression was left unsubstituted"
        return script

    def run(self, tmp_path: Path, action: dict, case: str, **inputs: str) -> tuple[int, dict]:
        import shutil
        import subprocess

        plan = ROOT / "corpus" / "cases" / case / "plan.json"
        shutil.copy(plan, tmp_path / "plan.json")
        output = tmp_path / "github_output"
        output.write_text("")

        script = self.review_script(action, plan="plan.json", sarif="", **inputs)
        (tmp_path / "review.sh").write_text(script)

        env = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", "/tmp"),
            "GITHUB_OUTPUT": str(output),
            "PYTHONPATH": str(ROOT),
        }
        result = subprocess.run(
            ["bash", "-eo", "pipefail", "review.sh"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )
        parsed = dict(
            line.split("=", 1)
            for line in output.read_text().splitlines()
            if "=" in line
        )
        return result.returncode, parsed

    @pytest.fixture(autouse=True)
    def _needs_the_cli_on_path(self):
        import shutil

        if not shutil.which("pyrrho"):
            pytest.skip("pyrrho is not on PATH; run `pip install -e .`")

    def test_a_blocking_review_still_writes_its_outputs(self, tmp_path, action):
        """The regression. Exit 1 from the review must not kill the step."""
        code, outputs = self.run(
            tmp_path, action, "ne019-ingress-from-a-security-group-that-is-itself-open"
        )
        assert code == 0, "the step must survive a blocking review"
        assert outputs["verdict"] == "block"
        assert outputs["worst"] == "high"
        assert outputs["findings"] == "1"

    def test_a_clean_review_writes_a_passing_verdict(self, tmp_path, action):
        code, outputs = self.run(
            tmp_path, action, "nc002-preexisting-exposure-left-untouched"
        )
        assert code == 0
        assert outputs["verdict"] == "pass"
        assert outputs["worst"] == ""

    def test_both_report_files_are_produced(self, tmp_path, action):
        self.run(tmp_path, action, "ne001-ssh-opened-to-the-internet")
        assert (tmp_path / "pyrrho-report.json").read_text().strip().startswith("{")
        assert "## pyrrho:" in (tmp_path / "pyrrho-report.md").read_text()

    def test_the_markdown_path_output_matches_the_file_written(self, tmp_path, action):
        _, outputs = self.run(tmp_path, action, "ne001-ssh-opened-to-the-internet")
        assert (tmp_path / outputs["markdown"]).exists()

    def test_an_unreadable_plan_exits_two(self, tmp_path, action):
        import subprocess

        (tmp_path / "plan.json").write_text("not json")
        script = self.review_script(action, plan="plan.json", sarif="")
        (tmp_path / "review.sh").write_text(script)
        result = subprocess.run(
            ["bash", "-eo", "pipefail", "review.sh"],
            cwd=tmp_path,
            env={
                "PATH": os.environ["PATH"],
                "HOME": os.environ.get("HOME", "/tmp"),
                "GITHUB_OUTPUT": str(tmp_path / "out"),
            },
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2, result.stderr

    def test_empty_optional_inputs_do_not_break_the_script(self, tmp_path, action):
        """Every optional input defaults to an empty string."""
        code, outputs = self.run(
            tmp_path,
            action,
            "ne001-ssh-opened-to-the-internet",
            analyzers="",
            claim="",
            baseline="",
            **{"sarif-location": "", "attest": ""},
        )
        assert code == 0 and outputs["verdict"] == "block"

    def test_analyzer_and_claim_lists_are_split_and_trimmed(self, tmp_path, action):
        code, outputs = self.run(
            tmp_path,
            action,
            "ne001-ssh-opened-to-the-internet",
            analyzers=" network-exposure , real-diff ",
        )
        assert code == 0 and outputs["verdict"] == "block"

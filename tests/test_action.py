"""The composite Action is asserted like the workflow is.

An action.yml with a typo in an input name fails at the moment someone else
tries to use it, in their repository, with an error that points at their
workflow. These checks move that discovery here.
"""

from __future__ import annotations

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

    def test_no_step_hides_a_failure(self, action):
        """Same rule as the workflow: the exit code has to mean something.

        The review step captures pyrrho's exit code deliberately, so that the
        summary and the pull request comment are still written when the review
        blocks, and re-raises it in the last step. That is not the same as
        swallowing it.
        """
        offenders = [s.get("name") for s in action["runs"]["steps"] if s.get("continue-on-error")]
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

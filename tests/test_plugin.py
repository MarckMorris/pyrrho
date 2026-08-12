"""The plugin layout is asserted, not assumed.

Claude Code loads a plugin by convention: the manifest at a fixed path, agents
and skills at the plugin root rather than inside .claude-plugin/, frontmatter on
every agent file. Getting any of that wrong fails silently — the plugin loads
and the component simply is not there. These tests are the check that would
otherwise be a manual one someone forgets to repeat.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".claude-plugin" / "plugin.json"
AGENTS = ROOT / "agents"
SKILLS = ROOT / "skills"


def frontmatter(path: Path) -> dict[str, str]:
    """Parse the leading YAML block. Only flat key: value pairs are used here."""
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path} has no frontmatter block"
    _, block, _ = text.split("---\n", 2)
    fields: dict[str, str] = {}
    for line in block.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        assert ":" in line, f"{path}: unparseable frontmatter line {line!r}"
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


class TestManifest:
    def test_the_manifest_is_at_the_documented_path(self):
        assert MANIFEST.exists(), "plugin.json must live at .claude-plugin/plugin.json"

    def test_the_manifest_is_valid_json(self):
        json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_the_required_fields_are_present(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        assert data["name"] == "pyrrho"
        assert data["description"]
        assert data["version"]

    def test_the_manifest_version_matches_the_package(self):
        from pyrrho import __version__

        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        assert data["version"] == __version__

    def test_the_manifest_version_matches_pyproject(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if l.startswith("version ="))
        declared = line.split("=", 1)[1].strip().strip('"')
        from pyrrho import __version__

        assert declared == __version__


class TestComponentLocations:
    def test_component_directories_are_at_the_plugin_root(self):
        # The documented mistake: putting these inside .claude-plugin/.
        for name in ("agents", "skills", "bin"):
            assert (ROOT / name).is_dir(), f"{name}/ must be at the plugin root"
            assert not (ROOT / ".claude-plugin" / name).exists(), (
                f"{name}/ must not be inside .claude-plugin/"
            )

    def test_only_the_manifest_lives_in_the_claude_plugin_directory(self):
        entries = {p.name for p in (ROOT / ".claude-plugin").iterdir()}
        assert entries == {"plugin.json"}


class TestAgents:
    def test_both_agents_exist(self):
        names = {p.stem for p in AGENTS.glob("*.md")}
        assert names == {"real-diff", "network-exposure"}

    @pytest.mark.parametrize("agent", ["real-diff", "network-exposure"])
    def test_the_agent_declares_a_matching_name(self, agent):
        fields = frontmatter(AGENTS / f"{agent}.md")
        assert fields["name"] == agent

    @pytest.mark.parametrize("agent", ["real-diff", "network-exposure"])
    def test_the_agent_description_says_when_to_use_it(self, agent):
        fields = frontmatter(AGENTS / f"{agent}.md")
        assert len(fields["description"]) > 80
        assert "use when" in fields["description"].lower()

    @pytest.mark.parametrize("agent", ["real-diff", "network-exposure"])
    def test_the_agent_cannot_edit_files(self, agent):
        """The kit reviews; it does not change infrastructure or code."""
        tools = {t.strip() for t in frontmatter(AGENTS / f"{agent}.md")["tools"].split(",")}
        assert not tools & {"Edit", "Write", "NotebookEdit"}

    @pytest.mark.parametrize("agent", ["real-diff", "network-exposure"])
    def test_the_agent_names_the_analyzer_it_drives(self, agent):
        body = (AGENTS / f"{agent}.md").read_text(encoding="utf-8")
        assert f"--analyzer {agent}" in body

    @pytest.mark.parametrize("agent", ["real-diff", "network-exposure"])
    def test_the_agent_is_told_not_to_invent_findings(self, agent):
        body = (AGENTS / f"{agent}.md").read_text(encoding="utf-8").lower()
        assert "no invented" in body

    def test_the_real_diff_agent_is_forbidden_from_applying(self):
        body = (AGENTS / "real-diff.md").read_text(encoding="utf-8")
        assert "Do not run `terraform apply`" in body


class TestSkill:
    def test_the_skill_is_a_directory_with_a_skill_file(self):
        assert (SKILLS / "review" / "SKILL.md").exists()

    def test_the_skill_declares_a_description(self):
        fields = frontmatter(SKILLS / "review" / "SKILL.md")
        assert len(fields["description"]) > 80

    def test_the_skill_states_what_is_not_covered(self):
        body = (SKILLS / "review" / "SKILL.md").read_text(encoding="utf-8")
        assert "What this does not cover" in body
        for absent in ("IAM privilege escalation", "Blast radius", "Compliance drift"):
            assert absent in body

    def test_the_skill_documents_the_exit_codes(self):
        body = (SKILLS / "review" / "SKILL.md").read_text(encoding="utf-8")
        assert "`0` clean" in body and "`2` could not" in body


class TestWrapper:
    def test_the_wrapper_is_executable(self):
        mode = (ROOT / "bin" / "pyrrho").stat().st_mode
        assert mode & stat.S_IXUSR, "bin/pyrrho must be executable"

    def test_the_wrapper_runs_without_the_package_installed(self):
        env = {
            "PATH": f"{ROOT / 'bin'}:/usr/bin:/bin",
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        result = subprocess.run(
            ["pyrrho", "--list-analyzers"], capture_output=True, text=True, env=env
        )
        assert result.returncode == 0, result.stderr
        assert "network-exposure" in result.stdout
        assert "real-diff" in result.stdout

    def test_the_wrapper_reports_a_missing_interpreter_clearly(self):
        env = {
            "PATH": f"{ROOT / 'bin'}:/usr/bin:/bin",
            "PYRRHO_PYTHON": "python-that-does-not-exist",
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        result = subprocess.run(["pyrrho", "--version"], capture_output=True, text=True, env=env)
        assert result.returncode == 2
        assert "not found" in result.stderr


class TestSelfReview:
    def test_the_corpus_self_review_produces_valid_sarif(self, tmp_path):
        output = tmp_path / "corpus.sarif"
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "self_review.py"), "--output", str(output)],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        assert result.returncode == 0, result.stderr
        doc = json.loads(output.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"], "the corpus must produce findings"

    def test_every_result_points_at_a_file_that_exists(self, tmp_path):
        output = tmp_path / "corpus.sarif"
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "self_review.py"), "--output", str(output)],
            capture_output=True,
            check=True,
            cwd=ROOT,
        )
        doc = json.loads(output.read_text(encoding="utf-8"))
        for result in doc["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert (ROOT / uri).exists(), uri

    def test_fingerprints_are_unique_across_cases(self, tmp_path):
        output = tmp_path / "corpus.sarif"
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "self_review.py"), "--output", str(output)],
            capture_output=True,
            check=True,
            cwd=ROOT,
        )
        doc = json.loads(output.read_text(encoding="utf-8"))
        prints = [r["partialFingerprints"]["pyrrhoFinding/v1"] for r in doc["runs"][0]["results"]]
        assert len(prints) == len(set(prints))

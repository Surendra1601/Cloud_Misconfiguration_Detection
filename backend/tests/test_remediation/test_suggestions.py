"""Tests for SuggestionManager template loading."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from app.pipeline.remediation.models import (
    RemediationTemplate,
)
from app.pipeline.remediation.suggestions import (
    REMEDIATION_CHECK_MAP,
    SuggestionManager,
)

# Path to bundled templates
_TEMPLATES_DIR = (
    Path(__file__).parent.parent.parent
    / "app"
    / "pipeline"
    / "remediation"
    / "templates"
)


class TestSuggestionManagerInit:
    """Test template loading on init."""

    def test_loads_bundled_templates(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        assert mgr.get_template_count() == 22

    def test_empty_dir(self, tmp_path):
        mgr = SuggestionManager(
            template_dir=tmp_path
        )
        assert mgr.get_template_count() == 0

    def test_nonexistent_dir(self, tmp_path):
        missing = tmp_path / "missing"
        mgr = SuggestionManager(
            template_dir=missing
        )
        assert mgr.get_template_count() == 0

    def test_invalid_json_skipped(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json{{{")
        mgr = SuggestionManager(
            template_dir=tmp_path
        )
        assert mgr.get_template_count() == 0

    def test_invalid_schema_skipped(self, tmp_path):
        # Valid JSON but missing required fields
        bad = tmp_path / "bad.json"
        bad.write_text('{"foo": "bar"}')
        mgr = SuggestionManager(
            template_dir=tmp_path
        )
        assert mgr.get_template_count() == 0

    def test_mixed_valid_invalid(self, tmp_path):
        # One valid, one invalid
        good = tmp_path / "good.json"
        good.write_text(
            json.dumps(
                {
                    "remediation_id": "REM_99",
                    "title": "Test Fix",
                }
            )
        )
        bad = tmp_path / "bad.json"
        bad.write_text("broken")
        mgr = SuggestionManager(
            template_dir=tmp_path
        )
        assert mgr.get_template_count() == 1


class TestGetSuggestion:
    """Test individual template retrieval."""

    def test_get_existing(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        t = mgr.get_suggestion("REM_04")
        assert t.remediation_id == "REM_04"
        assert "S3" in t.title
        assert t.domain == "data_protection"
        assert t.severity == "critical"
        assert t.check_id == "CHECK_04"

    def test_get_missing_raises(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        with pytest.raises(KeyError, match="REM_99"):
            mgr.get_suggestion("REM_99")

    def test_each_template_has_id_and_title(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for rid in mgr.templates:
            t = mgr.get_suggestion(rid)
            assert t.remediation_id
            assert t.title

    def test_each_template_has_check_id(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for t in mgr.templates.values():
            assert t.check_id, (
                f"{t.remediation_id} missing check_id"
            )

    def test_each_template_has_domain(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for t in mgr.templates.values():
            assert t.domain, (
                f"{t.remediation_id} missing domain"
            )

    def test_each_template_has_severity(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for t in mgr.templates.values():
            assert t.severity in (
                "critical",
                "high",
                "medium",
                "low",
            ), (
                f"{t.remediation_id} bad severity: "
                f"{t.severity}"
            )

    def test_each_template_has_console_steps(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for t in mgr.templates.values():
            assert len(t.console_steps) >= 3, (
                f"{t.remediation_id} needs more steps"
            )

    def test_each_template_has_cli_command(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for t in mgr.templates.values():
            assert t.cli_command, (
                f"{t.remediation_id} missing CLI cmd"
            )

    def test_each_template_has_terraform(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for t in mgr.templates.values():
            assert t.terraform_snippet, (
                f"{t.remediation_id} missing Terraform"
            )

    def test_each_template_has_references(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        for t in mgr.templates.values():
            assert len(t.references) >= 2, (
                f"{t.remediation_id} needs more refs"
            )


class TestListSuggestions:
    """Test filtered listing."""

    def test_list_all(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        all_t = mgr.list_suggestions()
        assert len(all_t) == 22

    def test_filter_by_domain(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        results = mgr.list_suggestions(
            domain="data_protection"
        )
        assert len(results) >= 3
        for t in results:
            assert t.domain == "data_protection"

    def test_filter_by_severity(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        results = mgr.list_suggestions(
            severity="critical"
        )
        assert len(results) >= 3
        for t in results:
            assert t.severity == "critical"

    def test_filter_by_domain_and_severity(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        results = mgr.list_suggestions(
            domain="network", severity="critical"
        )
        for t in results:
            assert t.domain == "network"
            assert t.severity == "critical"

    def test_filter_no_match(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        results = mgr.list_suggestions(
            domain="nonexistent"
        )
        assert results == []


class TestRenderCliCommand:
    """Test CLI command variable substitution."""

    def test_render_s3(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        cmd = mgr.render_cli_command(
            "REM_04", BUCKET_NAME="my-bucket"
        )
        assert "my-bucket" in cmd
        assert "{BUCKET_NAME}" not in cmd

    def test_render_sg(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        cmd = mgr.render_cli_command(
            "REM_07", SG_ID="sg-abc123"
        )
        assert "sg-abc123" in cmd
        assert "{SG_ID}" not in cmd

    def test_render_ec2(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        cmd = mgr.render_cli_command(
            "REM_08", INSTANCE_ID="i-abc123"
        )
        assert "i-abc123" in cmd

    def test_render_cloudtrail(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        cmd = mgr.render_cli_command(
            "REM_05", TRAIL_NAME="main-trail"
        )
        assert "main-trail" in cmd

    def test_render_missing_id_raises(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        with pytest.raises(KeyError):
            mgr.render_cli_command("REM_99")

    def test_render_no_substitution(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        cmd = mgr.render_cli_command("REM_17")
        # EBS encryption has no placeholders
        assert "enable-ebs-encryption" in cmd


class TestGetDomains:
    """Test domain listing."""

    def test_returns_unique_domains(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        domains = mgr.get_domains()
        assert len(domains) >= 5
        assert "data_protection" in domains
        assert "identity_access" in domains
        assert "network" in domains
        assert "logging_monitoring" in domains

    def test_sorted(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        domains = mgr.get_domains()
        assert domains == sorted(domains)


class TestGetByCheckId:
    """Test reverse lookup by check_id."""

    def test_find_existing(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        t = mgr.get_by_check_id("CHECK_04")
        assert t is not None
        assert t.remediation_id == "REM_04"

    def test_find_cross_resource(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        t = mgr.get_by_check_id("CHECK_CROSS_01")
        assert t is not None
        assert t.remediation_id == "REM_CROSS_01"

    def test_missing_returns_none(self):
        mgr = SuggestionManager(
            template_dir=_TEMPLATES_DIR
        )
        assert mgr.get_by_check_id("CHECK_99") is None


class TestRemediationCheckMap:
    """Test remediation-to-check ID mapping."""

    def test_has_20_checks(self):
        standard = {
            k: v
            for k, v in REMEDIATION_CHECK_MAP.items()
            if not k.startswith("REM_CROSS")
        }
        assert len(standard) == 20

    def test_has_cross_resource(self):
        assert "REM_CROSS_01" in REMEDIATION_CHECK_MAP
        assert (
            REMEDIATION_CHECK_MAP["REM_CROSS_01"]
            == "CHECK_CROSS_01"
        )

    def test_mapping_consistency(self):
        for rem_id, check_id in (
            REMEDIATION_CHECK_MAP.items()
        ):
            assert rem_id.startswith("REM_")
            assert check_id.startswith("CHECK_")

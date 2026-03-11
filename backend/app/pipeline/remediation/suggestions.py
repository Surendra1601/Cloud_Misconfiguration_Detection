"""Tier 1 remediation suggestion manager.

Loads JSON remediation templates from disk and serves
them as structured guidance (console steps, CLI commands,
Terraform snippets, compliance references).
"""

import json
import logging
import re
from pathlib import Path

from app.pipeline.remediation.models import (
    RemediationTemplate,
)

logger = logging.getLogger(__name__)

_DEFAULT_TEMPLATE_DIR = (
    Path(__file__).parent / "templates"
)

# Maps remediation IDs to their check IDs
REMEDIATION_CHECK_MAP: dict[str, str] = {
    f"REM_{i:02d}": f"CHECK_{i:02d}"
    for i in range(1, 21)
}
REMEDIATION_CHECK_MAP["REM_CROSS_01"] = "CHECK_CROSS_01"


class SuggestionManager:
    """Manages Tier 1 remediation suggestion templates.

    Loads all JSON templates from the templates directory
    at initialization and serves them by remediation_id.

    Attributes:
        template_dir: Path to templates directory.
        templates: Loaded templates keyed by ID.

    Example:
        >>> mgr = SuggestionManager()
        >>> t = mgr.get_suggestion("REM_04")
        >>> t.title
        'Enable S3 Public Access Block'
    """

    def __init__(
        self,
        template_dir: str | Path | None = None,
    ) -> None:
        """Initialize and load all templates.

        Args:
            template_dir: Path to JSON templates.
                Defaults to bundled templates/ dir.
        """
        self.template_dir = Path(
            template_dir or _DEFAULT_TEMPLATE_DIR
        )
        self.templates: dict[str, RemediationTemplate] = (
            {}
        )
        self._load_templates()

    def _load_templates(self) -> None:
        """Load all JSON template files from disk."""
        if not self.template_dir.exists():
            logger.warning(
                "Template dir not found: %s",
                self.template_dir,
            )
            return

        for path in sorted(
            self.template_dir.glob("*.json")
        ):
            try:
                data = json.loads(path.read_text())
                template = RemediationTemplate(**data)
                self.templates[
                    template.remediation_id
                ] = template
                logger.debug(
                    "Loaded template: %s",
                    template.remediation_id,
                )
            except (json.JSONDecodeError, Exception) as e:
                logger.error(
                    "Failed to load template %s: %s",
                    path.name,
                    e,
                )

    def get_suggestion(
        self, remediation_id: str
    ) -> RemediationTemplate:
        """Get a remediation suggestion by ID.

        Args:
            remediation_id: Template ID (e.g. REM_04).

        Returns:
            The matching RemediationTemplate.

        Raises:
            KeyError: If remediation_id not found.
        """
        if remediation_id not in self.templates:
            raise KeyError(
                f"Remediation template not found: "
                f"{remediation_id}"
            )
        return self.templates[remediation_id]

    def list_suggestions(
        self,
        domain: str | None = None,
        severity: str | None = None,
    ) -> list[RemediationTemplate]:
        """List all templates, optionally filtered.

        Args:
            domain: Filter by security domain.
            severity: Filter by severity level.

        Returns:
            List of matching templates.
        """
        results = list(self.templates.values())
        if domain:
            results = [
                t
                for t in results
                if t.domain == domain
            ]
        if severity:
            results = [
                t
                for t in results
                if t.severity == severity
            ]
        return results

    def render_cli_command(
        self,
        remediation_id: str,
        **kwargs: str,
    ) -> str:
        """Render a CLI command with variable substitution.

        Replaces {PLACEHOLDER} tokens in the template's
        cli_command with provided keyword arguments.

        Args:
            remediation_id: Template ID.
            **kwargs: Variable substitutions.

        Returns:
            Rendered CLI command string.

        Raises:
            KeyError: If remediation_id not found.

        Example:
            >>> mgr = SuggestionManager()
            >>> cmd = mgr.render_cli_command(
            ...     "REM_04",
            ...     BUCKET_NAME="my-bucket",
            ... )
        """
        template = self.get_suggestion(remediation_id)
        cmd = template.cli_command
        for key, value in kwargs.items():
            cmd = cmd.replace(f"{{{key}}}", value)
        return cmd

    def get_template_count(self) -> int:
        """Return total number of loaded templates."""
        return len(self.templates)

    def get_domains(self) -> list[str]:
        """Return unique security domains."""
        return sorted(
            {
                t.domain
                for t in self.templates.values()
                if t.domain
            }
        )

    def get_by_check_id(
        self, check_id: str
    ) -> RemediationTemplate | None:
        """Look up template by its linked check_id.

        Args:
            check_id: Policy check ID (e.g. CHECK_04).

        Returns:
            Matching template or None.
        """
        for t in self.templates.values():
            if t.check_id == check_id:
                return t
        return None

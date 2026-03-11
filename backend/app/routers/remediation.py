"""Remediation REST API endpoints.

Tier 1: GET suggestions (any user).
Tier 2: POST execute one-click fixes.
Rollback: POST rollback within window.
Audit: GET audit trail.
Config: GET/PUT auto-remediation config.
"""

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from pydantic import BaseModel

from app.auth import require_auth, require_operator
from app.config import Settings
from app.dependencies import (
    get_audit_manager,
    get_auto_engine,
    get_config_manager,
    get_one_click_remediator,
    get_rollback_manager,
    get_settings,
    get_suggestion_manager,
)
from app.pipeline.remediation.audit_manager import (
    AuditManager,
)
from app.pipeline.remediation.auto_remediate import (
    AutoRemediationEngine,
)
from app.pipeline.remediation.config_manager import (
    ConfigManager,
)
from app.pipeline.remediation.models import (
    AutoRemediationConfig,
    RemediationTemplate,
)
from app.pipeline.remediation.one_click import (
    OneClickRemediator,
)
from app.pipeline.remediation.rollback import (
    RollbackManager,
)
from app.pipeline.remediation.suggestions import (
    SuggestionManager,
)

router = APIRouter(
    tags=["remediation"],
    dependencies=[Depends(require_auth)],
)


# --- Request/Response Models ---


class ExecuteRequest(BaseModel):
    """Request body for one-click execution."""

    resource_arn: str
    account_id: str | None = None
    confirm: bool = False
    initiated_by: str = "api-user"


class RollbackRequest(BaseModel):
    """Request body for rollback."""

    action_id: str
    account_id: str | None = None


class ConfigRequest(BaseModel):
    """Request body for config updates."""

    account_id: str | None = None
    check_id: str
    enabled: bool = True
    rollback_window_minutes: int = 60
    notify_on_action: bool = True
    approved_by: str = ""


# --- Audit Trail (before {remediation_id}) ---


@router.get("/remediation/audit")
def list_audit(
    account_id: str | None = Query(
        None,
        description="AWS account ID",
    ),
    check_id: str | None = Query(
        None, description="Filter by check_id"
    ),
    limit: int = Query(
        50, ge=1, le=500, description="Max results"
    ),
    audit_mgr: AuditManager = Depends(
        get_audit_manager
    ),
    settings: Settings = Depends(get_settings),
) -> dict:
    """List remediation audit trail."""
    actual_account_id = account_id or settings.aws_account_id
    entries = audit_mgr.list_actions(
        account_id=actual_account_id,
        check_id=check_id,
        limit=limit,
    )
    return {
        "entries": [
            {
                "action_id": e.action_id,
                "remediation_id": e.remediation_id,
                "check_id": e.check_id,
                "resource_arn": e.resource_arn,
                "action_taken": e.action_taken,
                "tier": e.tier.value,
                "initiated_by": e.initiated_by,
                "status": e.status.value,
                "rollback_deadline": (
                    e.rollback_deadline
                ),
                "created_at": e.created_at,
            }
            for e in entries
        ],
        "total": len(entries),
    }


# --- Auto-Remediation Config (before {id}) ---


@router.get("/remediation/config")
def list_configs(
    account_id: str | None = Query(
        None,
        description="AWS account ID",
    ),
    enabled_only: bool = Query(
        False, description="Only show enabled"
    ),
    config_mgr: ConfigManager = Depends(
        get_config_manager
    ),
    settings: Settings = Depends(get_settings),
) -> dict:
    """List auto-remediation configs."""
    actual_account_id = account_id or settings.aws_account_id
    configs = config_mgr.list_configs(
        account_id=actual_account_id,
        enabled_only=enabled_only,
    )
    return {
        "configs": [
            c.model_dump() for c in configs
        ],
        "total": len(configs),
    }


@router.put("/remediation/config")
def set_config(
    body: ConfigRequest,
    config_mgr: ConfigManager = Depends(
        get_config_manager
    ),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Create or update auto-remediation config."""
    actual_account_id = body.account_id or settings.aws_account_id
    config = AutoRemediationConfig(
        account_id=actual_account_id,
        check_id=body.check_id,
        enabled=body.enabled,
        rollback_window_minutes=(
            body.rollback_window_minutes
        ),
        notify_on_action=body.notify_on_action,
        approved_by=body.approved_by,
    )
    ok = config_mgr.set_config(config)
    if not ok:
        raise HTTPException(
            status_code=500,
            detail="Failed to save config",
        )
    return {
        "status": "saved",
        "account_id": body.account_id,
        "check_id": body.check_id,
        "enabled": body.enabled,
    }


# --- Tier 1: Suggestions ---


@router.get("/remediation")
def list_suggestions(
    domain: str | None = Query(
        None,
        description="Filter by security domain",
    ),
    severity: str | None = Query(
        None,
        description="Filter by severity",
    ),
    suggestion_mgr: SuggestionManager = Depends(
        get_suggestion_manager
    ),
) -> dict:
    """List all remediation suggestions."""
    templates = suggestion_mgr.list_suggestions(
        domain=domain, severity=severity
    )
    return {
        "remediations": [
            t.model_dump() for t in templates
        ],
        "total": len(templates),
    }


@router.get("/remediation/{remediation_id}")
def get_suggestion(
    remediation_id: str,
    suggestion_mgr: SuggestionManager = Depends(
        get_suggestion_manager
    ),
) -> dict:
    """Get remediation suggestion (Tier 1).

    Returns console steps, CLI command, Terraform
    snippet, and compliance references.
    """
    try:
        template = suggestion_mgr.get_suggestion(
            remediation_id
        )
        return template.model_dump()
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Remediation {remediation_id} "
                f"not found"
            ),
        )


# --- Tier 2: One-Click Execute ---


@router.post(
    "/remediation/{remediation_id}/execute"
)
def execute_remediation(
    remediation_id: str,
    body: ExecuteRequest,
    role: str = Depends(require_operator),
    one_click: OneClickRemediator = Depends(
        get_one_click_remediator
    ),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Execute a one-click remediation (Tier 2).

    Requires confirm=true in the request body.
    """
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="confirm must be true",
        )

    try:
        action = one_click.execute(
            remediation_id=remediation_id,
            resource_arn=body.resource_arn,
            account_id=body.account_id or settings.aws_account_id,
            initiated_by=body.initiated_by,
        )
        return {
            "action_id": action.action_id,
            "status": action.status.value,
            "remediation_id": (
                action.remediation_id
            ),
            "resource_arn": action.resource_arn,
            "rollback_available_until": (
                action.rollback_available_until
            ),
            "error_message": action.error_message,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail=str(e)
        )


# --- Rollback ---


@router.post(
    "/remediation/{remediation_id}/rollback"
)
def rollback_remediation(
    remediation_id: str,
    body: RollbackRequest,
    role: str = Depends(require_operator),
    rollback_mgr: RollbackManager = Depends(
        get_rollback_manager
    ),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Rollback a previous remediation action."""
    result = rollback_mgr.rollback(
        action_id=body.action_id,
        account_id=body.account_id or settings.aws_account_id,
    )
    if result["status"] == "error":
        raise HTTPException(
            status_code=400,
            detail=result["message"],
        )
    return result

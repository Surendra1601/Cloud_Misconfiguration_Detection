"""Compliance score endpoint — reads from DynamoDB."""

from fastapi import APIRouter, Depends

from app.auth import require_auth
from app.dependencies import (
    get_settings,
    get_state_manager,
)
from app.pipeline.state_manager import StateManager

router = APIRouter(
    tags=["compliance"],
    dependencies=[Depends(require_auth)],
)


@router.get("/compliance/score")
def get_compliance_score(
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> dict:
    """Compute compliance score from stored state.

    Reads all persisted violation states and
    returns aggregated compliance metrics.
    Field names match the frontend ComplianceScore type:
      passed, failed, errors, skipped, by_domain,
      by_severity.
    """
    states = state_manager.query_by_account(
        settings.aws_account_id,
        settings.aws_region,
        limit=5000,
    )

    total = len(states)
    alarms = 0
    compliant = 0
    errors = 0
    skipped = 0

    by_domain: dict[str, dict] = {}
    by_severity: dict[str, int] = {}

    for s in states:
        # Count by status
        if s.status == "alarm":
            alarms += 1
        elif s.status == "ok":
            compliant += 1
        elif s.status == "error":
            errors += 1
        elif s.status == "skip":
            skipped += 1

        # Aggregate by_severity — only count violations
        if s.status == "alarm" and s.severity:
            sev = s.severity.lower()
            by_severity[sev] = (
                by_severity.get(sev, 0) + 1
            )

        # Aggregate by_domain
        d = s.domain or "unknown"
        if d not in by_domain:
            by_domain[d] = {
                "total": 0,
                "alarm": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
        by_domain[d]["total"] += 1
        if s.status == "alarm":
            by_domain[d]["alarm"] += 1
            sev = getattr(s, "severity", "medium") or "medium"
            sev = sev.lower()
            if sev in ["critical", "high", "medium", "low"]:
                by_domain[d][sev] += 1

    score_total = alarms + compliant
    score_pct = (
        round(compliant / score_total * 100)
        if score_total > 0
        else 100
    )

    domain_scores: dict[str, dict] = {}
    for d, counts in by_domain.items():
        passing = counts["total"] - counts["alarm"]
        pct = (
            round(passing / counts["total"] * 100)
            if counts["total"] > 0
            else 100
        )
        domain_scores[d] = {
            "score_percent": pct,
            "total": counts["total"],
            "passed": passing,
            "alarm": counts["alarm"],
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
        }

    return {
        "score_percent": score_pct,
        "total_checks": total,
        "passed": compliant,
        "failed": alarms,
        "errors": errors,
        "skipped": skipped,
        "by_domain": domain_scores,
        "by_severity": by_severity,
    }


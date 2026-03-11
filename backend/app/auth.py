"""Authentication and authorization dependencies."""

from fastapi import Depends, Header, HTTPException
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from app.config import Settings
from app.dependencies import get_settings

bearer = HTTPBearer()


def require_auth(
    creds: HTTPAuthorizationCredentials = Depends(
        bearer
    ),
    settings: Settings = Depends(get_settings),
):
    """Validate Bearer token against API key.

    Rejects requests without a valid API key.
    Swap to Cognito JWT validation later.
    """
    if creds.credentials != settings.api_key:
        raise HTTPException(
            status_code=403, detail="Forbidden"
        )
    return creds.credentials


def require_operator(
    _: str = Depends(require_auth),
    x_user_role: str | None = Header(
        None, alias="X-User-Role"
    ),
):
    """Require operator or admin role.

    Used for destructive endpoints like execute
    and rollback.
    """
    if x_user_role not in (
        "operator",
        "administrator",
    ):
        raise HTTPException(
            403, "Operator role required"
        )
    return x_user_role

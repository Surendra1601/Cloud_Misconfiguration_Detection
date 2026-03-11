"""FastAPI application entry point."""

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from app.config import _auto_generate_api_key, settings
from app.routers import (
    compliance,
    drift,
    policies,
    remediation,
    risk,
    scans,
    violations,
    websocket,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle — runs scheduled scans."""
    import threading
    from uuid import uuid4

    from app.dependencies import (
        get_boto3_session,
        get_evaluator,
        get_settings as _get_settings,
        get_state_manager,
    )
    from app.routers.scans import _run_scan

    if settings.aws_account_id == "123456789012":
        logger.warning(
            "AWS_ACCOUNT_ID is the default "
            "placeholder. Set it in .env for "
            "production use."
        )
    if settings.api_key == "change-me-in-env":
        key = _auto_generate_api_key()
        settings.api_key = key

    interval = settings.scan_interval_minutes * 60  # seconds
    stop_event = threading.Event()

    def _scheduler_loop():
        """Run in a daemon thread — fires _run_scan every interval."""
        logger.info(
            "Scheduled scanner started — interval: %d min",
            settings.scan_interval_minutes,
        )
        while not stop_event.wait(timeout=0):
            scan_id = str(uuid4())
            logger.info("Auto-scan starting [%s]", scan_id)
            try:
                _run_scan(
                    scan_id=scan_id,
                    session=get_boto3_session(),
                    settings=_get_settings(),
                    evaluator=get_evaluator(),
                    state_manager=get_state_manager(),
                )
                logger.info(
                    "Auto-scan complete [%s]", scan_id
                )
            except Exception as exc:
                logger.error(
                    "Auto-scan [%s] crashed: %s",
                    scan_id, exc, exc_info=True,
                )
            # Wait for the next interval (or until stop_event is set)
            stop_event.wait(timeout=interval)

    scheduler = threading.Thread(
        target=_scheduler_loop,
        name="cloudline-scheduler",
        daemon=True,
    )
    scheduler.start()

    yield  # application is running

    logger.info("Stopping scheduled scanner…")
    stop_event.set()
    scheduler.join(timeout=10)


app = FastAPI(
    title="CloudLine",
    description=(
        "OPA-based AWS misconfiguration "
        "detection platform"
    ),
    version=settings.app_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        o.strip()
        for o in settings.cors_origins.split(",")
        if o.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- Security Headers ---
@app.middleware("http")
async def security_headers(
    request: Request, call_next
):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = (
        "nosniff"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'"
    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000; includeSubDomains"
    path = request.url.path
    if not path.startswith(
        "/api/docs"
    ) and not path.startswith("/api/openapi"):
        response.headers[
            "Cache-Control"
        ] = "no-store, no-cache, must-revalidate"
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )
    return response

app.include_router(
    scans.router, prefix="/api/v1"
)
app.include_router(
    violations.router, prefix="/api/v1"
)
app.include_router(
    compliance.router, prefix="/api/v1"
)
app.include_router(
    drift.router, prefix="/api/v1"
)
app.include_router(
    risk.router, prefix="/api/v1"
)
app.include_router(
    remediation.router, prefix="/api/v1"
)
app.include_router(
    policies.router, prefix="/api/v1"
)
app.include_router(websocket.router)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/v1/auth/login")
async def login(body: LoginRequest):
    """Dev login — returns the API key as a token.

    In production, swap this for Cognito/OIDC.
    """
    if not body.username or not body.password:
        raise HTTPException(
            400, "Username and password required"
        )
    return {
        "token": settings.api_key,
        "user": {
            "sub": "local-user",
            "email": body.username
            if "@" in body.username
            else f"{body.username}@cloudline.dev",
            "name": body.username.split("@")[0],
            "role": "admin",
        },
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "cloudline-backend",
        "version": settings.app_version,
    }

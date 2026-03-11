"""Rego policy management endpoints.

List, create, and delete OPA/Rego policies
from the policies directory.
"""

import re
from enum import Enum
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel, Field

from app.auth import require_auth, require_operator
from app.config import Settings
from app.dependencies import get_settings

router = APIRouter(
    tags=["policies"],
    dependencies=[Depends(require_auth)],
)

# --- Constants ---

DOMAIN_DIRS: dict[str, str] = {
    "identity": "domain_1_identity",
    "data_protection": "domain_2_data_protection",
    "network": "domain_3_network",
    "logging": "domain_4_logging",
    "detection": "domain_5_detection",
}

# Map input_field to the Rego input path
INPUT_FIELD_MAP: dict[str, str] = {
    "iam": "input.iam",
    "s3": "input.s3",
    "ec2": "input.ec2",
    "rds": "input.rds",
    "cloudtrail": "input.cloudtrail",
    "lambda": "input.lambda_functions",
    "vpc": "input.vpc",
    "guardduty": "input.guardduty",
    "config": "input.config",
    "cloudwatch": "input.cloudwatch",
    "kms": "input.kms",
    "ebs": "input.ebs",
    "backup": "input.backup",
    "secretsmanager": "input.secretsmanager",
    "nacl": "input.ec2",
}


class DomainEnum(str, Enum):
    identity = "identity"
    data_protection = "data_protection"
    network = "network"
    logging = "logging"
    detection = "detection"


class SeverityEnum(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


# --- Request/Response Models ---


class ComplianceMappings(BaseModel):
    """Compliance framework mappings."""

    cis_aws: list[str] = Field(default_factory=list)
    nist_800_53: list[str] = Field(
        default_factory=list
    )
    pci_dss: list[str] = Field(default_factory=list)


class PolicyInfo(BaseModel):
    """Policy metadata extracted from .rego file."""

    filename: str
    package_name: str
    check_id: str
    domain: str
    severity: str
    path: str


class CreatePolicyRequest(BaseModel):
    """Request body for creating a new policy."""

    check_id: str = Field(
        ...,
        pattern=r"^CHECK_\d+$",
        description="e.g. CHECK_21",
    )
    domain: DomainEnum
    severity: SeverityEnum
    description: str = Field(
        ..., min_length=5, max_length=200
    )
    input_field: str = Field(
        ..., description="e.g. iam, s3, ec2"
    )
    resource_pattern: str = Field(
        ...,
        description=(
            "Rego resource path, "
            "e.g. input.s3.buckets[_]"
        ),
    )
    compliance: ComplianceMappings = Field(
        default_factory=ComplianceMappings
    )
    remediation_id: str = Field(
        ...,
        pattern=r"^REM_\d+$",
        description="e.g. REM_21",
    )


# --- Helpers ---


def _resolve_policy_dir(
    settings: Settings,
) -> Path:
    """Resolve the absolute policies directory."""
    policy_dir = Path(settings.opa_policy_dir)
    if not policy_dir.is_absolute():
        # Relative to backend root
        backend_root = (
            Path(__file__).resolve().parent.parent.parent
        )
        policy_dir = (backend_root / policy_dir).resolve()
    return policy_dir


def _extract_metadata(
    rego_path: Path,
    policy_dir: Path,
) -> PolicyInfo | None:
    """Extract metadata from a .rego file."""
    try:
        content = rego_path.read_text()
    except OSError:
        return None

    pkg_match = re.search(
        r"^package\s+([\w.]+)", content, re.MULTILINE
    )
    if not pkg_match:
        return None
    package_name = pkg_match.group(1)

    check_match = re.search(
        r'"check_id":\s*"(CHECK_\d+)"', content
    )
    if not check_match:
        return None
    check_id = check_match.group(1)

    domain_match = re.search(
        r'"domain":\s*"(\w+)"', content
    )
    domain = (
        domain_match.group(1) if domain_match else ""
    )

    severity_match = re.search(
        r'"severity":\s*"(\w+)"', content
    )
    severity = (
        severity_match.group(1)
        if severity_match
        else ""
    )

    rel_path = str(rego_path.relative_to(policy_dir))

    return PolicyInfo(
        filename=rego_path.name,
        package_name=package_name,
        check_id=check_id,
        domain=domain,
        severity=severity,
        path=rel_path,
    )


def _generate_rego(req: CreatePolicyRequest) -> str:
    """Generate a .rego policy file from request."""
    # Derive package suffix from check_id
    num = req.check_id.split("_")[1]
    # Sanitize description for package name
    slug = re.sub(
        r"[^a-z0-9]+",
        "_",
        req.description.lower(),
    ).strip("_")
    pkg_name = f"aws.check_{num}_{slug}"

    input_path = INPUT_FIELD_MAP.get(
        req.input_field, f"input.{req.input_field}"
    )
    # Extract the top-level input key
    input_key = input_path.replace("input.", "")
    # For error rule: use the first segment
    input_top = input_key.split(".")[0]

    cis = _format_list(req.compliance.cis_aws)
    nist = _format_list(req.compliance.nist_800_53)
    pci = _format_list(req.compliance.pci_dss)

    return f"""package {pkg_name}

violations contains result if {{
\tresource := {req.resource_pattern}
\tresult := {{
\t\t"check_id": "{req.check_id}",
\t\t"status": "alarm",
\t\t"severity": "{req.severity.value}",
\t\t"reason": "{req.description}",
\t\t"resource": resource.arn,
\t\t"domain": "{req.domain.value}",
\t\t"compliance": {{
\t\t\t"cis_aws": [{cis}],
\t\t\t"nist_800_53": [{nist}],
\t\t\t"pci_dss": [{pci}],
\t\t}},
\t\t"remediation_id": "{req.remediation_id}",
\t}}
}}

error contains result if {{
\tnot {input_path}
\tresult := {{
\t\t"check_id": "{req.check_id}",
\t\t"status": "error",
\t\t"severity": "{req.severity.value}",
\t\t"reason": "{input_top.upper()} data missing from input",
\t\t"resource": "",
\t\t"domain": "{req.domain.value}",
\t}}
}}
"""


def _format_list(items: list[str]) -> str:
    """Format a list of strings for Rego."""
    if not items:
        return ""
    return ", ".join(f'"{i}"' for i in items)


# --- Endpoints ---


@router.get("/policies")
def list_policies(
    settings: Settings = Depends(get_settings),
) -> dict:
    """List all Rego policies.

    Scans the policies directory for .rego files
    (excluding tests) and extracts metadata.
    """
    policy_dir = _resolve_policy_dir(settings)
    if not policy_dir.is_dir():
        raise HTTPException(
            status_code=500,
            detail="Policies directory not found",
        )

    policies: list[dict] = []
    for rego_path in sorted(policy_dir.rglob("*.rego")):
        # Skip test files
        if "_test.rego" in rego_path.name:
            continue
        # Skip risk_scoring and cross_resource
        parent = rego_path.parent.name
        if parent in (
            "risk_scoring",
            "cross_resource",
            "tests",
        ):
            continue

        info = _extract_metadata(rego_path, policy_dir)
        if info:
            policies.append(info.model_dump())

    return {
        "policies": policies,
        "total": len(policies),
    }


@router.post("/policies", status_code=201)
def create_policy(
    body: CreatePolicyRequest,
    role: str = Depends(require_operator),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Create a new Rego policy file.

    Generates a .rego file in the appropriate
    domain directory.
    """
    policy_dir = _resolve_policy_dir(settings)

    # Validate domain directory exists
    domain_dir_name = DOMAIN_DIRS.get(
        body.domain.value
    )
    if not domain_dir_name:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown domain: {body.domain}",
        )
    domain_path = policy_dir / domain_dir_name
    if not domain_path.is_dir():
        domain_path.mkdir(parents=True, exist_ok=True)

    # Check for duplicate check_id
    for rego_path in policy_dir.rglob("*.rego"):
        if "_test.rego" in rego_path.name:
            continue
        try:
            content = rego_path.read_text()
        except OSError:
            continue
        if f'"check_id": "{body.check_id}"' in content:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{body.check_id} already exists"
                ),
            )

    # Generate filename
    num = body.check_id.split("_")[1]
    slug = re.sub(
        r"[^a-z0-9]+",
        "_",
        body.description.lower(),
    ).strip("_")
    filename = f"check_{num}_{slug}.rego"
    file_path = domain_path / filename

    if file_path.exists():
        raise HTTPException(
            status_code=409,
            detail=f"File {filename} already exists",
        )

    # Write the policy
    rego_content = _generate_rego(body)
    file_path.write_text(rego_content)

    rel_path = str(
        file_path.relative_to(policy_dir)
    )
    return {
        "status": "created",
        "check_id": body.check_id,
        "filename": filename,
        "path": rel_path,
    }


@router.delete("/policies/{check_id}")
def delete_policy(
    check_id: str,
    role: str = Depends(require_operator),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Delete a policy file by check_id.

    Searches all domain directories for the
    matching check_id and removes the file.
    """
    policy_dir = _resolve_policy_dir(settings)
    if not policy_dir.is_dir():
        raise HTTPException(
            status_code=500,
            detail="Policies directory not found",
        )

    # Validate check_id format
    if not re.match(r"^CHECK_\d+$", check_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid check_id format",
        )

    # Find the policy file
    for rego_path in policy_dir.rglob("*.rego"):
        if "_test.rego" in rego_path.name:
            continue
        try:
            content = rego_path.read_text()
        except OSError:
            continue
        if f'"check_id": "{check_id}"' in content:
            rel_path = str(
                rego_path.relative_to(policy_dir)
            )
            rego_path.unlink()
            return {
                "status": "deleted",
                "check_id": check_id,
                "path": rel_path,
            }

    raise HTTPException(
        status_code=404,
        detail=f"Policy {check_id} not found",
    )

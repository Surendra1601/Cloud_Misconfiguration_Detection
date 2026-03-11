# CloudLine — Code Review: Open-Source & Local Fixes

**Reviewer**: Senior Engineer  
**Date**: 2026-03-03  
**Context**: Open-source project for **local use** — users run this against their own AWS accounts.  
**Scope**: Full codebase — 50+ Python files, 22 Rego policies, Terraform, Docker, scripts  
**Verdict**: ⚠️ **Core features broken** — risk scoring, violations listing, and data storage have critical bugs. Fix before publicizing.

---

## Summary

The architecture is solid and well-decomposed. However, several **core features silently don't work** (risk scoring, violations listing, compliance scoring all trigger live AWS scans or return empty data), and there are **data corruption bugs** that would cause users to lose violation records. These must be fixed for the tool to deliver on its promise.

---

## Table of Contents

- [🔴 CRITICAL — Broken Functionality](#-critical--broken-functionality)
- [🟠 HIGH — Correctness & Reliability](#-high--correctness--reliability)
- [🟡 MEDIUM — Performance & Code Quality](#-medium--performance--code-quality)
- [🔵 LOW — Technical Debt](#-low--technical-debt)
- [📐 Design & Extensibility](#-design--extensibility)

---

## 🔴 CRITICAL — Broken Functionality

### C-01: Three Endpoints Trigger Full AWS Scans on Every Request

| | |
|---|---|
| **File(s)** | [violations.py](file:///home/parrot/CloudLine/backend/app/routers/violations.py) L48–54, [compliance.py](file:///home/parrot/CloudLine/backend/app/routers/compliance.py) L32–40, [scans.py](file:///home/parrot/CloudLine/backend/app/routers/scans.py) L17–23 |
| **Problem** | `GET /violations`, `GET /compliance/score`, and `POST /scans` each create a new `CollectionOrchestrator` and call `collect_full()` — dozens of AWS API calls + 20 OPA evaluations on every request. Dashboard refresh takes 10–60s. `/scans` also dumps raw AWS config as JSON without evaluating or persisting anything. |
| **Impact** | Unusable latency, AWS throttling, and the scan doesn't produce or store violations. |
| **Fix** | `POST /scans` → run evaluation + persist to DynamoDB + return summary. `GET /violations` and `GET /compliance/score` → read from DynamoDB via `StateManager`. |

---

### C-02: RiskScorer Data Format Mismatch — Scoring Is Completely Non-Functional

| | |
|---|---|
| **File** | [risk_scorer.py](file:///home/parrot/CloudLine/backend/app/pipeline/risk_scorer.py) |
| **Problem** | Methods expect PascalCase AWS API keys (`PublicAccessBlockConfiguration`, `IpPermissions`, `HttpTokens`, etc.) but collectors output snake_case (`public_access_block`, `ingress_rules`, `http_tokens`). **3 of 5 scoring dimensions always return defaults.** |
| **Impact** | Every violation gets the same generic score. The multi-dimensional risk scoring — a core feature — doesn't work. |
| **Fix** | Update all key lookups to match `models/aws_input.py` snake_case schema. |

---

### C-03: Empty ARNs for Security Groups and EBS Volumes — Data Corruption

| | |
|---|---|
| **File** | [ec2.py](file:///home/parrot/CloudLine/backend/app/collectors/ec2.py) L189, L219 |
| **Problem** | `"arn": ""` for SGs and EBS volumes. DynamoDB sort key is `{check_id}#{resource_arn}` — empty ARNs cause all SG/EBS violations for the same check to **overwrite each other**. 100 SGs produce 1 record. |
| **Fix** | Construct: `f"arn:aws:ec2:{region}:{account}:security-group/{sg_id}"`, `f"arn:aws:ec2:{region}:{account}:volume/{vol_id}"`. |

---

### C-04: DynamoDB 1MB Query Truncation — Silent Data Loss

| | |
|---|---|
| **File** | [state_manager.py](file:///home/parrot/CloudLine/backend/app/pipeline/state_manager.py) — all 5 query methods + `count_by_status()`, also [audit_manager.py](file:///home/parrot/CloudLine/backend/app/pipeline/remediation/audit_manager.py) `count_actions()`, `list_actions()`, [config_manager.py](file:///home/parrot/CloudLine/backend/app/pipeline/remediation/config_manager.py) `list_configs()` |
| **Problem** | DynamoDB returns max 1MB per query page. None of the methods handle `LastEvaluatedKey`. ~1,600 items per page → accounts with 4,000+ violation records lose 60%+ of data, including counts. |
| **Fix** | Pagination loops with `ExclusiveStartKey` on all query methods. |

```python
def query_by_status(self, status, limit=100):
    items = []
    kwargs = {
        "IndexName": "status-index",
        "KeyConditionExpression": Key("status").eq(status),
        "ScanIndexForward": False,
    }
    while True:
        resp = self.table.query(**kwargs)
        items.extend(resp.get("Items", []))
        if len(items) >= limit:
            return [_item_to_state(i) for i in items[:limit]]
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return [_item_to_state(i) for i in items]
```

---

### C-05: IAM Collector Reports Quota Instead of Actual Active Key Count

| | |
|---|---|
| **File** | [iam.py](file:///home/parrot/CloudLine/backend/app/collectors/iam.py) L50–53 |
| **Problem** | Uses `AccessKeysPerUserQuota` (always 2) instead of `AccessKeysActive`. |
| **Fix** | Change to `s.get("AccessKeysActive", 0)`. |

---

## 🟠 HIGH — Correctness & Reliability

### H-01: No IPv6 Handling — Collectors, Rego Policies, AND Remediation

| | |
|---|---|
| **File(s)** | `ec2.py` `_build_security_group`, `vpc.py` `_get_nacls`, `check_07_security_groups.rego`, `check_15_nacls.rego`, `one_click.py` `_fix_security_group_ssh` |
| **Problem** | Collectors skip `Ipv6Ranges`/`Ipv6CidrBlock`. Rego only checks `rule.cidr == "0.0.0.0/0"`. SG remediation only revokes IPv4, not IPv6 `::/0`. A `::/0` SSH rule is completely invisible to the entire stack. |
| **Fix** | 1. Add IPv6 iteration in collectors. 2. Add `::/0` check in Rego. 3. Add IPv6 revocation in remediation. |

---

### H-02: `update_status()` DynamoDB Race Condition

| | |
|---|---|
| **File** | [state_manager.py](file:///home/parrot/CloudLine/backend/app/pipeline/state_manager.py) L165–171 |
| **Problem** | `SET #st = :new_status, previous_status = #st` — left-to-right evaluation corrupts `previous_status`. |
| **Fix** | Reverse: `SET previous_status = #st, #st = :new_status`. |

---

### H-03: `REM_07b` Not Registered — RDP Remediation Crashes

| | |
|---|---|
| **File(s)** | [check_07](file:///home/parrot/CloudLine/policies/domain_3_network/check_07_security_groups.rego) L48, [one_click.py](file:///home/parrot/CloudLine/backend/app/pipeline/remediation/one_click.py) L29–35 |
| **Problem** | RDP violation emits `remediation_id: "REM_07b"` but only `"REM_07"` is registered. One-click fix for RDP raises `ValueError`. |
| **Fix** | Register `REM_07b` in `_EXECUTORS` and `_ROLLBACK_HANDLERS`. |

---

### H-04: EC2 STS Call Per Instance

| **File** | `ec2.py` L76–82 |
| **Problem** | 100 instances = 100 redundant `get_caller_identity()` calls. |
| **Fix** | Pass `account_id` from orchestrator. |

---

### H-05: Missing Pagination in AWS API Calls

| **Files** | `ec2.py` `_get_security_groups`, `vpc.py` `_get_vpcs`, `_get_flow_logs`, `_get_nacls` |
| **Fix** | Use boto3 paginators (already used for `describe_instances`). |

---

### H-06: OPA CLI Temp Files Leak AWS Config on Crash

| **File** | `opa_cli.py` L45–51 |
| **Fix** | Use `subprocess.run(input=...)` to pipe via stdin. |

---

### H-07: Rego Policies Don't Generate OK Results for Passing Resources

| | |
|---|---|
| **File** | [check_07](file:///home/parrot/CloudLine/policies/domain_3_network/check_07_security_groups.rego) (and most others) |
| **Problem** | Unlike `check_04` (S3), most policies only generate `violations` — no `compliant` results for passing resources. The evaluator can't count total checked resources, making `score_percent` inaccurate. |
| **Fix** | Add `compliant` rules to all Rego policies for passing resources. |

---

### H-08: `RollbackManager` Does O(n) Full Scan for Sort Key

| | |
|---|---|
| **File** | [rollback.py](file:///home/parrot/CloudLine/backend/app/pipeline/remediation/rollback.py) L146–159 |
| **Problem** | Fetches ALL audit entries to linear-scan for `action_id`, then reconstructs the sort key from the result. |
| **Fix** | Add GSI on `action_id`, or store `sk` in `RemediationAction`. |

---

### H-09: `AutoRemediationEngine` Records Wrong Tier

| | |
|---|---|
| **File** | [auto_remediate.py](file:///home/parrot/CloudLine/backend/app/pipeline/remediation/auto_remediate.py) L134 |
| **Problem** | Comment says "Override tier to AUTO" but it's never done. All auto-actions show as `tier_2_oneclick` in audit. |
| **Fix** | Update the audit record tier after `execute()`. |

---

### H-10: `drift.py` Misclassifies Stable "ok" States as Resolutions

| **File** | `drift.py` L112–115 |
| **Fix** | Only classify as RESOLUTION when `previous_status == "alarm"` and `status == "ok"`. |

---

### H-11: `risk_score.rego` `risk_score_5d` Has No Default Rule

| **File** | [risk_score.rego](file:///home/parrot/CloudLine/policies/risk_scoring/risk_score.rego) L19 |
| **Fix** | Add `default risk_score_5d(_) := 0`. |

---

### H-12: SG Rollback Silently Swallows Exceptions

| | |
|---|---|
| **File** | [rollback.py](file:///home/parrot/CloudLine/backend/app/pipeline/remediation/rollback.py) L301–302 |
| **Problem** | `except Exception: pass` — failed rollback appears successful. |
| **Fix** | Log errors, report partial failures. |

---

### H-12b: No Local RBAC — Anyone Running the App Can Execute Remediations

| | |
|---|---|
| **File(s)** | All `backend/app/routers/` — especially [remediation.py](file:///home/parrot/CloudLine/backend/app/routers/remediation.py), [scans.py](file:///home/parrot/CloudLine/backend/app/routers/scans.py). Missing file: `backend/app/auth/rbac.py` (specified in blueprint L288 but never created). |
| **Problem** | The blueprint (§10.6) defines 3 roles with clear permission boundaries: |

| Role | Permissions (per blueprint) |
|---|---|
| **Viewer** | Read compliance scores, violations, trends, reports |
| **Operator** | Viewer + trigger Tier 2 one-click remediation + trigger scans |
| **Administrator** | Operator + configure Tier 3 auto-remediation + manage settings + manage users |

Even for **local/open-source use**, RBAC matters:

- A security team uses CloudLine as a shared internal tool — a **manager or auditor** should be able to view compliance dashboards but **must not** be able to execute remediations (which modify live AWS infrastructure).
- A **security engineer** (Operator) can trigger one-click fixes for critical findings.
- Only the **team lead / admin** should be able to enable Tier 3 auto-remediation or change its configuration — because auto-remediation runs **unattended** and modifies infrastructure automatically.

Currently, every endpoint is completely open. There's no `rbac.py` file despite the blueprint specifying one at `backend/app/auth/rbac.py`.

| | |
|---|---|
| **Impact** | Without role separation, a junior team member or non-security stakeholder with dashboard access can accidentally (or intentionally) trigger remediation actions that modify production AWS resources — revoke security group rules, enable encryption on running services, change instance metadata options, or enable auto-remediation. The audit trail records all actions as `"api-user"`, making it impossible to trace who did what. |
| **Fix** | Implement lightweight local RBAC (no Cognito needed for local use): |

```python
# backend/app/auth/rbac.py

from enum import Enum
from fastapi import Depends, HTTPException, Header

class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMINISTRATOR = "administrator"

# Role hierarchy: admin > operator > viewer
_ROLE_HIERARCHY = {
    Role.VIEWER: 0,
    Role.OPERATOR: 1,
    Role.ADMINISTRATOR: 2,
}

def require_role(minimum_role: Role):
    """FastAPI dependency for role-based route guards."""
    def _check(x_cloudline_role: str = Header(default="viewer")):
        try:
            user_role = Role(x_cloudline_role.lower())
        except ValueError:
            raise HTTPException(403, "Invalid role")
        if _ROLE_HIERARCHY[user_role] < _ROLE_HIERARCHY[minimum_role]:
            raise HTTPException(
                403,
                f"Requires {minimum_role.value}+ role, "
                f"you have {user_role.value}",
            )
        return user_role
    return _check
```

Apply per the blueprint's endpoint spec:

| Endpoint | Required Role |
|---|---|
| `GET /violations`, `GET /compliance/*`, `GET /drift/*` | **Viewer+** |
| `POST /scans`, `POST /remediation/{id}/execute`, `POST /remediation/{id}/rollback` | **Operator+** |
| `PUT /remediation/config` (auto-remediation on/off) | **Administrator** |

For local use, this can be a simple header-based approach (`X-CloudLine-Role: operator`) that the frontend sets based on the logged-in user's config. Optional: add a `users.yaml` config file mapping usernames to roles for teams sharing one deployment.

---

## 🟡 MEDIUM — Performance & Code Quality

| ID | Issue | File(s) | Fix |
|---|---|---|---|
| M-01 | `_extract_packages()` duplicated in both OPA clients | `opa_cli.py`, `opa_http.py` | Extract to shared utility |
| M-02 | KMS dual-collect + fragile `[-1]` index | `kms.py`, `orchestrator.py` | Split or use named lookup |
| M-03 | `OPAHTTPClient` — no connection pooling | `opa_http.py` | Reuse `httpx.Client` |
| M-04 | `LoggingCollector.collect_resource()` only CloudTrail | `logging_collector.py` | Add resource type routing |
| M-05 | `S3Collector` calls versioning API twice per bucket | `s3.py` | Merge into one call |
| M-06 | Deprecated `datetime.utcnow()` | `pipeline/models.py` L140 | Use `datetime.now(UTC)` |
| M-07 | Hardcoded OPA path `/home/parrot/.local/bin/opa` | `opa_cli.py` L21 | Default to `"opa"` (use PATH) |
| M-08 | `risk.py` uses `limit*2` over-fetch hack | `risk.py` L59, L67 | Server-side filter or paginate |
| M-09 | `risk.py` calls private `_scorer._categorize()` | `risk.py` L75 | Make `categorize()` public |
| M-10 | `BaseCollector._safe_call()` dead code | `base.py` L47–57 | Use or remove; add error field |
| M-11 | `capital_one_scenario.rego` only 4 hardcoded policies | `capital_one_scenario.rego` | Pattern-match `*FullAccess` |
| M-12 | No structured logging | All files | Add `structlog` |
| M-13 | `docker-compose.yml` deprecated `version` key | `docker-compose.yml` | Remove `version: "3.9"` |
| M-14 | `_EXECUTORS` uses lowercase `callable` annotation | `one_click.py` L485 | Use `Callable` from `typing` |
| M-15 | Remediation defaults `account_id` to `"123456789012"` | `remediation.py` L59, L68 | Make required field |

---

## 🔵 LOW — Technical Debt

| ID | Issue | Fix |
|---|---|---|
| L-01 | No `__all__` exports | Define public API in `__init__.py` |
| L-02 | No graceful WebSocket shutdown | Send close frames |
| L-03 | Missing `Content-Security-Policy` header | Add CSP |
| L-04 | WebSocket auth accepts any non-empty string | Remove fake check or document it |
| L-05 | CORS defaults may not match production frontend URL | Environment-aware config |
| L-06 | Rollback deadline timezone mismatch risk | Ensure all timestamps include tz |

---

## 📐 Design & Extensibility

| ID | Issue | Fix |
|---|---|---|
| D-01 | New collector requires 3 edits to orchestrator | Auto-discovery registry pattern |
| D-02 | `EventHandler` creates own dependencies | Accept via constructor (DI) |
| D-03 | `LoggingCollector` bundles 4 services | Split into focused collectors |
| D-04 | No circuit breaker for AWS/OPA calls | Add `tenacity` retry + backoff |
| D-05 | No error differentiation in collectors | Add `errors` field to output |
| D-06 | `event-correlation` table used in code but missing in init script | Add to `init-dynamodb.sh` |

> [!NOTE]
> Wait — the `event-correlation` table IS in `init-dynamodb.sh` at line 81. This finding was incorrect. However, the Terraform modules should be verified to match.

---

## 🚨 NEW FINDINGS (Added in Second-Round Review)

### C-06 (NEW): FastAPI Async Starvation (Event Loop Blocking)

| | |
|---|---|
| **File(s)** | All files in `backend/app/routers/` (e.g. `scans.py`, `violations.py`) |
| **Problem** | Endpoint functions are defined with `async def`, but they execute 100% synchronous I/O operations (boto3 `collect_full()`, DynamoDB queries, OPA HTTP requests). Unlike standard `def` routes which run in a thread pool, FastAPI runs `async def` routes on the main ASGI event loop. |
| **Impact** | **Catastrophic.** A single user triggering a scan (10-60 seconds) will completely block the FastAPI web server. All other incoming API requests will hang and eventually time out. Under any concurrent load, the system crashes. |
| **Fix** | 1. Change all `async def` to regular `def` for synchronous handlers, allowing FastAPI/Starlette to run them in an external thread pool. 2. Alternatively, wrap all boto3/requests calls in `asyncio.get_running_loop().run_in_executor()`. |

---

### H-13 (NEW): O(N) Database Network Operations for Persistence

| | |
|---|---|
| **File** | `event_handler.py` L118-133, `state_manager.py` |
| **Problem** | `EventHandler.process_event` loops over multiple matched policies for a single event. Inside this loop, it calls `state_manager.put_state(new_state)` sequentially. For an event triggering 10 policies, this causes 10 synchronous POST requests to DynamoDB. |
| **Impact** | Extreme latency spikes during event processing and high risk of DynamoDB write throttling. |
| **Fix** | Implement `StateManager.batch_put()` using DynamoDB's `BatchWriteItem` API to save all states for a resource in a single network call. |

---

### H-14 (NEW): Uncached boto3.Session Creation in API Dependencies

| | |
|---|---|
| **File** | `dependencies.py` L40-44 |
| **Problem** | `get_boto3_session()` lacks the `@lru_cache` decorator. It instantiates a new `boto3.Session` on **every single API request**. |
| **Impact** | `boto3.Session` creation requires reading AWS credentials from disk/env and setting up STS context. Doing this per-request adds significant blocked I/O latency to every endpoint. |
| **Fix** | Add `@lru_cache` to `get_boto3_session()` or instantiate the session once at the module level. |

---

## Priority Order

> [!CAUTION]
> **Fix First** — Core functionality is broken:

1. **C-01**: Three endpoints trigger live scans (unusable)
2. **C-02**: RiskScorer data format (scoring doesn't work)
3. **C-03**: Empty ARNs (data corruption)
4. **C-04**: DynamoDB 1MB truncation (silent data loss)
5. **C-05**: Wrong IAM field
6. **C-06 (NEW)**: FastAPI Async Starvation (Event Loop Blocking)

> [!WARNING]
> **Fix Before Release** — Correctness:

6. **H-01–H-03**: IPv6 blind spot across full stack
7. **H-02**: DynamoDB update race condition
8. **H-03**: REM_07b crashes
9. **H-04–H-06**: STS per instance, pagination, temp files
10. **H-07**: Rego OK results missing
11. **H-08–H-12**: Rollback bugs, wrong audit tier, drift misclassification
11b. **H-12b**: Local RBAC — prevent non-security staff from executing remediations
12. **H-13–H-14 (NEW)**: O(N) DB calls, uncached boto3.Session

> [!IMPORTANT]
> **Fix For Good DX** — For contributors and users:

12. **M-07**: Hardcoded OPA path (every contributor hits this day 1)
13. **M-15**: Default account IDs
14. **D-01**: Collector auto-discovery (contribution friction)
15. **D-05**: Error differentiation (debugging)
16. Everything else

---

*Based on line-by-line review of all 50+ source files, 22 Rego policies, Terraform, Docker, scripts, and test fixtures.*

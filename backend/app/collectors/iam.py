"""IAM service collector."""

import logging
from datetime import datetime, timezone

from botocore.config import Config

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)

_IAM_CONFIG = Config(
    retries={
        "max_attempts": 5,
        "mode": "adaptive",
    }
)


class IAMCollector(BaseCollector):
    """Collects IAM account summary, password policy,
    users with access keys/MFA, and Access Analyzer."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client(
            "iam", config=_IAM_CONFIG
        )
        return "iam", {
            "account_summary": self._get_account_summary(
                client
            ),
            "password_policy": self._get_password_policy(
                client
            ),
            "users": self._get_users(client),
            "access_analyzer": self._get_access_analyzer(),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client(
            "iam", config=_IAM_CONFIG
        )
        try:
            user = client.get_user(UserName=resource_id)
            return self._build_user_dict(
                client, user["User"]
            )
        except client.exceptions.NoSuchEntityException:
            return {}

    def _get_account_summary(self, client) -> dict:
        try:
            summary = client.get_account_summary()
            s = summary["SummaryMap"]
            return {
                "mfa_enabled": s.get(
                    "AccountMFAEnabled", 0
                )
                == 1,
                "users": s.get("Users", 0),
                "access_keys_active": s.get(
                    "AccessKeysActive", 0
                ),
            }
        except Exception:
            return {
                "mfa_enabled": False,
                "users": 0,
                "access_keys_active": 0,
            }

    def _get_password_policy(self, client) -> dict:
        try:
            pp = client.get_account_password_policy()
            policy = pp["PasswordPolicy"]
            return {
                "minimum_length": policy.get(
                    "MinimumPasswordLength", 8
                ),
                "require_symbols": policy.get(
                    "RequireSymbols", False
                ),
                "require_numbers": policy.get(
                    "RequireNumbers", False
                ),
                "require_uppercase": policy.get(
                    "RequireUppercaseCharacters", False
                ),
                "require_lowercase": policy.get(
                    "RequireLowercaseCharacters", False
                ),
                "max_age_days": policy.get(
                    "MaxPasswordAge", 0
                ),
                "password_reuse_prevention": policy.get(
                    "PasswordReusePrevention", 0
                ),
                "hard_expiry": policy.get(
                    "HardExpiry", False
                ),
            }
        except client.exceptions.NoSuchEntityException:
            return {
                "minimum_length": 8,
                "require_symbols": False,
                "require_numbers": False,
                "require_uppercase": False,
                "require_lowercase": False,
                "max_age_days": 0,
                "password_reuse_prevention": 0,
                "hard_expiry": False,
            }

    def _get_users(self, client) -> list[dict]:
        users = []
        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                users.append(
                    self._build_user_dict(client, user)
                )
        return users

    def _build_user_dict(
        self, client, user: dict
    ) -> dict:
        username = user["UserName"]
        arn = user["Arn"]

        # MFA devices
        mfa_devices = client.list_mfa_devices(
            UserName=username
        )
        mfa_enabled = (
            len(mfa_devices["MFADevices"]) > 0
        )

        # Access keys
        keys = client.list_access_keys(
            UserName=username
        )
        access_keys = []
        for k in keys["AccessKeyMetadata"]:
            last_used_days = None
            try:
                lu = client.get_access_key_last_used(
                    AccessKeyId=k["AccessKeyId"]
                )
                last_used = lu.get(
                    "AccessKeyLastUsed", {}
                ).get("LastUsedDate")
                if last_used:
                    delta = (
                        datetime.now(timezone.utc)
                        - last_used
                    )
                    last_used_days = delta.days
            except Exception:
                pass
            access_keys.append(
                {
                    "key_id": k["AccessKeyId"],
                    "status": k["Status"],
                    "created_date": k[
                        "CreateDate"
                    ].isoformat(),
                    "last_used_days_ago": last_used_days,
                }
            )

        # Attached policies
        attached = client.list_attached_user_policies(
            UserName=username
        )
        policies = [
            {
                "policy_name": p["PolicyName"],
                "policy_arn": p["PolicyArn"],
            }
            for p in attached["AttachedPolicies"]
        ]

        # Last activity
        last_activity_days = None
        pwd_last_used = user.get("PasswordLastUsed")
        if pwd_last_used:
            delta = (
                datetime.now(timezone.utc)
                - pwd_last_used
            )
            last_activity_days = delta.days

        return {
            "name": username,
            "arn": arn,
            "mfa_enabled": mfa_enabled,
            "access_keys": access_keys,
            "last_activity_days_ago": last_activity_days,
            "attached_policies": policies,
        }

    def _get_access_analyzer(self) -> dict:
        try:
            client = self.session.client(
                "accessanalyzer"
            )
            resp = client.list_analyzers(
                Type="ACCOUNT"
            )
            analyzers = [
                {
                    "name": a["name"],
                    "arn": a["arn"],
                    "status": a["status"],
                }
                for a in resp.get("analyzers", [])
            ]
            return {"analyzers": analyzers}
        except Exception:
            return {"analyzers": []}

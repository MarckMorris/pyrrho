"""Real-diff analyzer: what the plan actually does, versus what it appears to do.

A Terraform plan is read by humans as a list of resource names with a symbol
next to each one. Three things routinely hide in that rendering:

* ``-/+`` is a destroy. For a database, a volume or a log group it is a destroy
  that takes the data with it, and the plan says so only in a line most reviewers
  scroll past.
* ``(known after apply)`` means the plan is not a prediction of the outcome. A
  reviewer who approves it is approving a value nobody has seen.
* Drift means the plan was computed against a state file that no longer matches
  reality, so the diff shown is a diff against fiction.

This analyzer reports those, plus the case where the plan touches resources the
change was never claimed to touch.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from ..core import Analyzer, Finding, Severity, register
from ..plan import Plan, ResourceChange

# Destroying one of these destroys data that is not in version control.
STATEFUL: dict[str, str] = {
    "aws_db_instance": "relational database and its data",
    "aws_rds_cluster": "database cluster and its data",
    "aws_rds_cluster_instance": "database cluster member",
    "aws_docdb_cluster": "DocumentDB cluster and its data",
    "aws_neptune_cluster": "Neptune cluster and its data",
    "aws_redshift_cluster": "Redshift cluster and its data",
    "aws_dynamodb_table": "DynamoDB table and its items",
    "aws_s3_bucket": "S3 bucket and its objects",
    "aws_ebs_volume": "EBS volume and its filesystem",
    "aws_efs_file_system": "EFS filesystem and its contents",
    "aws_fsx_lustre_file_system": "FSx filesystem and its contents",
    "aws_elasticache_cluster": "ElastiCache node and its keyspace",
    "aws_elasticache_replication_group": "ElastiCache replication group and its keyspace",
    "aws_msk_cluster": "Kafka cluster and its topics",
    "aws_opensearch_domain": "OpenSearch domain and its indices",
    "aws_elasticsearch_domain": "Elasticsearch domain and its indices",
    "aws_timestreamwrite_table": "Timestream table and its records",
    "aws_qldb_ledger": "QLDB ledger and its journal",
    "aws_kms_key": "KMS key, making everything it encrypted unreadable",
    "aws_secretsmanager_secret": "secret and its versions",
    "aws_cloudwatch_log_group": "log group and its retained events",
    "aws_glacier_vault": "Glacier vault and its archives",
    "aws_backup_vault": "backup vault and its recovery points",
    "aws_ecr_repository": "container registry and its images",
    "google_sql_database_instance": "Cloud SQL instance and its data",
    "google_storage_bucket": "GCS bucket and its objects",
    "azurerm_storage_account": "storage account and its containers",
    "azurerm_mssql_database": "SQL database and its data",
}

# Replacing one of these interrupts traffic unless the new one is created first.
TRAFFIC_SERVING: dict[str, str] = {
    "aws_lb": "load balancer",
    "aws_alb": "load balancer",
    "aws_elb": "load balancer",
    "aws_instance": "instance",
    "aws_ecs_service": "ECS service",
    "aws_lambda_function": "Lambda function",
    "aws_api_gateway_rest_api": "API Gateway API",
    "aws_cloudfront_distribution": "CloudFront distribution",
    "aws_autoscaling_group": "autoscaling group",
    "aws_eks_node_group": "EKS node group",
    "aws_nat_gateway": "NAT gateway",
}

# Attributes whose only job is to stop an accidental destroy.
GUARDS: dict[str, tuple[str, ...]] = {
    "aws_db_instance": ("deletion_protection",),
    "aws_rds_cluster": ("deletion_protection",),
    "aws_lb": ("enable_deletion_protection",),
    "aws_alb": ("enable_deletion_protection",),
    "aws_dynamodb_table": ("deletion_protection_enabled",),
    "aws_eks_cluster": (),
    "aws_docdb_cluster": ("deletion_protection",),
    "aws_neptune_cluster": ("deletion_protection",),
    "google_sql_database_instance": ("deletion_protection",),
}

# Attributes that are dangerous when switched ON rather than off.
INVERSE_GUARDS: dict[str, tuple[str, ...]] = {
    "aws_db_instance": ("skip_final_snapshot",),
    "aws_rds_cluster": ("skip_final_snapshot",),
    "aws_docdb_cluster": ("skip_final_snapshot",),
    "aws_neptune_cluster": ("skip_final_snapshot",),
    "aws_s3_bucket": ("force_destroy",),
    "aws_ecr_repository": ("force_delete",),
}

# Turning any of these off, or destroying them, removes the record of what
# happens next. It is the standard first move, and it is invisible to a check
# that only asks whether the end state violates a policy: after the change there
# is simply no trail resource left to have an opinion about.
AUDIT_TRAIL: dict[str, tuple[str, str]] = {
    "aws_cloudtrail": ("enable_logging", "API call history for the account"),
    "aws_flow_log": ("", "VPC flow logs, the record of what talked to what"),
    "aws_config_configuration_recorder": ("", "the configuration history AWS Config keeps"),
    "aws_config_configuration_recorder_status": ("is_enabled", "AWS Config recording"),
    "aws_guardduty_detector": ("enable", "GuardDuty threat detection"),
    "aws_securityhub_account": ("", "Security Hub findings aggregation"),
    "aws_s3_bucket_logging": ("", "S3 server access logs"),
    # aws_cloudwatch_log_group is deliberately absent: it is already in STATEFUL,
    # so destroying it reports RD001. Listing it here too would produce two
    # findings for one destroy.
}

# Attributes that decide whether you can get back to where you were. Each is a
# one-token diff that changes nothing on apply, which is exactly why it reads as
# harmless in review.
RECOVERABILITY: dict[str, dict[str, str]] = {
    "aws_db_instance": {
        "backup_retention_period": "zero disables automated backups and deletes the ones already taken",
        "delete_automated_backups": "true discards retained backups when the instance goes",
        "copy_tags_to_snapshot": "",
    },
    "aws_rds_cluster": {
        "backup_retention_period": "zero disables automated backups and deletes the ones already taken",
    },
    "aws_s3_bucket_versioning": {
        "status": "suspending versioning means an overwrite is final",
    },
    "aws_cloudwatch_log_group": {
        "retention_in_days": "shortening retention discards history you may need for an incident",
    },
    "aws_dynamodb_table": {
        "point_in_time_recovery": "disabling PITR removes the only way back from a bad write",
    },
    "aws_efs_file_system": {
        "backup_policy": "",
    },
}

# Attributes worth flagging when the plan cannot resolve them before apply.
SECURITY_RELEVANT_UNKNOWNS: tuple[str, ...] = (
    "policy",
    "assume_role_policy",
    "kms_key_id",
    "kms_key_arn",
    "user_data",
    "iam_instance_profile",
    "role_arn",
    "acl",
    "encrypted",
    "storage_encrypted",
)

# Terraform's own words for why a resource is going away. Some of these mean
# "somebody deleted the block", which is a different conversation from
# "the provider forces a replacement".
ACTION_REASONS: dict[str, str] = {
    "delete_because_no_resource_config": "the resource block was removed from the configuration",
    "delete_because_no_module": "the module call was removed from the configuration",
    "delete_because_count_index": "the count was reduced and this index no longer exists",
    "delete_because_each_key": "the for_each key was removed",
    "delete_because_wrong_repetition": "count/for_each was switched and the address changed",
    "replace_because_tainted": "the resource is tainted",
    "replace_because_cannot_update": "an immutable attribute changed, so the provider must recreate it",
    "replace_by_request": "a -replace flag was passed on the command line",
}


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return False


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _pitr_enabled(value: Any) -> bool:
    """point_in_time_recovery is a nested block, so it arrives as a list."""
    if isinstance(value, list):
        return any(_truthy(v.get("enabled")) for v in value if isinstance(v, dict))
    if isinstance(value, dict):
        return _truthy(value.get("enabled"))
    return _truthy(value)


def _reason(rc: ResourceChange) -> str:
    return ACTION_REASONS.get(rc.action_reason, rc.action_reason or "not stated by Terraform")


@register
class RealDiff(Analyzer):
    """Reports the consequences of the plan that its rendering does not show."""

    name = "real-diff"
    description = (
        "Finds destroys hidden inside replacements, values unknown until apply, "
        "removed safety guards, state drift, and resources outside the declared scope."
    )

    def __init__(self, claim: list[str] | None = None) -> None:
        # Patterns describing what the change is supposed to touch. fnmatch
        # syntax, matched against the Terraform address.
        self.claim = list(claim or [])

    def configure(self, **options: Any) -> None:
        claim = options.get("claim")
        if claim:
            self.claim = list(claim)

    def run(self, plan: Plan) -> list[Finding]:
        findings: list[Finding] = []
        for rc in plan.effective_changes:
            findings.extend(self._data_loss(rc))
            findings.extend(self._downtime(rc))
            findings.extend(self._guards(rc))
            findings.extend(self._sensitive(rc))
            findings.extend(self._unknowns(rc))
            findings.extend(self._audit_trail(rc))
            findings.extend(self._recoverability(rc))
        findings.extend(self._drift(plan))
        findings.extend(self._scope(plan))
        return findings

    # -- destroys ---------------------------------------------------------

    def _data_loss(self, rc: ResourceChange) -> list[Finding]:
        if not rc.destroys_data or rc.type not in STATEFUL:
            return []

        what = STATEFUL[rc.type]
        replacing = rc.is_replace
        rule = "RD002" if replacing else "RD001"
        title = (
            "Stateful resource replaced, destroying its data"
            if replacing
            else "Stateful resource destroyed"
        )
        verb = (
            "will be destroyed and recreated"
            if replacing
            else "will be destroyed and not recreated"
        )

        detail = (
            f"This plan {verb}. That takes the {what} with it. "
            f"Terraform renders this as {'-/+' if replacing else '-'} on one line."
        )
        if replacing:
            paths = [".".join(p) for p in rc.replace_paths]
            if paths:
                detail += f" The replacement is forced by: {', '.join(paths)}."

        evidence: dict[str, Any] = {
            "actions": list(rc.actions),
            "action_reason": _reason(rc),
            "replace_paths": [".".join(p) for p in rc.replace_paths],
            "resource_type": rc.type,
        }
        for key in ("identifier", "name", "bucket", "table_name", "db_name"):
            if rc.prior(key) is not None:
                evidence[key] = rc.prior(key)

        # A final snapshot is the difference between "recoverable" and "gone".
        for key in ("skip_final_snapshot", "final_snapshot_identifier"):
            if key in rc.before or key in rc.after:
                evidence[key] = {"before": rc.prior(key), "after": rc.value(key)}

        return [
            self.finding(
                rule,
                title,
                Severity.CRITICAL,
                rc.address,
                detail,
                evidence=evidence,
                remediation=(
                    "If the destroy is intended, take a verified snapshot first and confirm the "
                    "restore path. If it is not, add a lifecycle prevent_destroy block and find "
                    "which attribute forces the replacement."
                    if replacing
                    else "Confirm the resource block was removed on purpose. Terraform will not "
                    "warn again at apply time when the plan is pre-approved."
                ),
            )
        ]

    def _downtime(self, rc: ResourceChange) -> list[Finding]:
        if not rc.is_replace or rc.type not in TRAFFIC_SERVING:
            return []
        if rc.is_create_before_destroy:
            return []

        what = TRAFFIC_SERVING[rc.type]
        return [
            self.finding(
                "RD003",
                "Replacement destroys before creating, so traffic stops",
                Severity.MEDIUM,
                rc.address,
                f"This {what} is replaced with destroy-then-create. There is a window with no "
                f"{what} at all, lasting as long as provisioning takes. "
                f"create_before_destroy would remove the window.",
                evidence={
                    "actions": list(rc.actions),
                    "action_reason": _reason(rc),
                    "replace_paths": [".".join(p) for p in rc.replace_paths],
                },
                remediation=(
                    "Add lifecycle { create_before_destroy = true }. Check that names and other "
                    "unique attributes are generated, since two copies exist briefly."
                ),
            )
        ]

    # -- guards -----------------------------------------------------------

    def _guards(self, rc: ResourceChange) -> list[Finding]:
        findings: list[Finding] = []

        for key in GUARDS.get(rc.type, ()):
            if key not in rc.before and key not in rc.after:
                continue
            if _truthy(rc.prior(key)) and not _truthy(rc.value(key)):
                findings.append(
                    self.finding(
                        "RD004",
                        "Deletion protection removed",
                        Severity.HIGH,
                        rc.address,
                        f"{key} goes from true to false. On its own this changes nothing; it "
                        f"removes the control that would have stopped the next plan from "
                        f"destroying this resource. That next plan may not get this review.",
                        evidence={key: {"before": rc.prior(key), "after": rc.value(key)}},
                        remediation=(
                            f"Leave {key} enabled. If a destroy is genuinely intended, disable "
                            f"it and destroy in the same change so the intent is auditable."
                        ),
                        key=key,
                    )
                )

        for key in INVERSE_GUARDS.get(rc.type, ()):
            if key not in rc.before and key not in rc.after:
                continue
            if not _truthy(rc.prior(key)) and _truthy(rc.value(key)):
                findings.append(
                    self.finding(
                        "RD004",
                        "Destroy safety net disabled",
                        Severity.HIGH,
                        rc.address,
                        f"{key} goes from false to true, which lets a future destroy proceed "
                        f"without leaving anything behind to restore from.",
                        evidence={key: {"before": rc.prior(key), "after": rc.value(key)}},
                        remediation=(
                            f"Keep {key} disabled outside of a deliberate teardown, and take a "
                            f"snapshot before enabling it."
                        ),
                        key=key,
                    )
                )

        return findings

    # -- hidden values ----------------------------------------------------

    def _sensitive(self, rc: ResourceChange) -> list[Finding]:
        if rc.is_create or rc.is_delete:
            return []

        rotated = sorted(
            key
            for key in set(rc.after_sensitive) | set(rc.before_sensitive)
            if rc.is_sensitive(key) and rc.changed(key)
        )
        if not rotated:
            return []

        return [
            self.finding(
                "RD006",
                "Sensitive value changes without showing what changed",
                Severity.MEDIUM,
                rc.address,
                f"{', '.join(rotated)} is marked sensitive, so Terraform prints "
                f"(sensitive value) instead of the diff. The change is real and unreviewable "
                f"from the plan alone; anything consuming the old value breaks at apply.",
                evidence={
                    "sensitive_attributes_changed": rotated,
                    "actions": list(rc.actions),
                },
                remediation=(
                    "Confirm out of band which value changed and what reads it. Consider moving "
                    "the value to a secrets manager and referencing it, so rotation is not a "
                    "Terraform diff at all."
                ),
            )
        ]

    def _unknowns(self, rc: ResourceChange) -> list[Finding]:
        hidden = [k for k in SECURITY_RELEVANT_UNKNOWNS if rc.is_unknown(k)]
        if not hidden:
            return []

        return [
            self.finding(
                "RD008",
                "Security-relevant attribute is unknown until apply",
                Severity.MEDIUM,
                rc.address,
                f"Terraform cannot resolve {', '.join(hidden)} at plan time. Approving this "
                f"plan approves a value nobody has seen, on an attribute that decides who can "
                f"read what.",
                evidence={
                    "unknown_attributes": hidden,
                    "actions": list(rc.actions),
                    "all_unknown": rc.unknown_keys(),
                },
                remediation=(
                    "Pin the value to a literal or a data source that resolves at plan time, or "
                    "re-run this review against the post-apply state before the change is "
                    "considered approved."
                ),
            )
        ]

    def _audit_trail(self, rc: ResourceChange) -> list[Finding]:
        """The record of what happens is being destroyed or switched off."""
        if rc.type not in AUDIT_TRAIL:
            return []
        toggle, what = AUDIT_TRAIL[rc.type]
        if not what:
            return []

        destroyed = rc.destroys_data
        switched_off = bool(toggle) and _truthy(rc.prior(toggle)) and not _truthy(rc.value(toggle))
        if not destroyed and not switched_off:
            return []

        action = "destroyed" if destroyed else "switched off"
        return [
            self.finding(
                "RD009",
                "Audit or logging trail removed",
                Severity.HIGH,
                rc.address,
                f"This plan leaves {what} {action}. Nothing else in the change needs to be "
                f"wrong for that to matter: it removes the ability to find out later what "
                f"any of the rest of it did.",
                evidence={
                    "actions": list(rc.actions),
                    "action_reason": _reason(rc),
                    "resource_type": rc.type,
                    "toggle": (
                        {toggle: {"before": rc.prior(toggle), "after": rc.value(toggle)}}
                        if toggle
                        else None
                    ),
                    "name": rc.prior("name") or rc.value("name"),
                },
                remediation=(
                    "Keep the trail. If it is being replaced by something else in the same "
                    "change, say which resource takes over and confirm the handover leaves no "
                    "gap. If the destination bucket is the problem, fix the bucket."
                ),
                key=rc.type,
            )
        ]

    def _recoverability(self, rc: ResourceChange) -> list[Finding]:
        """A safety net removed without anything appearing to change."""
        attributes = RECOVERABILITY.get(rc.type)
        if not attributes:
            return []

        findings: list[Finding] = []
        for key, why in attributes.items():
            if not why or (key not in rc.before and key not in rc.after):
                continue

            before_value = rc.prior(key)
            after_value = rc.value(key)
            if before_value == after_value:
                continue

            weakened = False
            if key == "backup_retention_period":
                weakened = _as_int(after_value, 0) < _as_int(before_value, 0)
            elif key == "retention_in_days":
                # Zero means "keep forever" for a CloudWatch log group, so it is
                # the one value that is not a reduction.
                after_days = _as_int(after_value, 0)
                before_days = _as_int(before_value, 0)
                weakened = before_days != 0 and (after_days == 0 or after_days < before_days) and after_days != 0
            elif key == "status":
                weakened = str(before_value).lower() == "enabled" and str(after_value).lower() != "enabled"
            elif key == "point_in_time_recovery":
                weakened = _pitr_enabled(before_value) and not _pitr_enabled(after_value)
            elif key == "delete_automated_backups":
                weakened = not _truthy(before_value) and _truthy(after_value)

            if not weakened:
                continue

            findings.append(
                self.finding(
                    "RD010",
                    "Recoverability weakened",
                    Severity.HIGH,
                    rc.address,
                    f"{key} goes from {before_value!r} to {after_value!r}: {why}. Applying this "
                    f"changes nothing you can see. It changes what is possible after the next "
                    f"mistake.",
                    evidence={key: {"before": before_value, "after": after_value}},
                    remediation=(
                        f"Leave {key} as it was unless someone has confirmed the restore path "
                        f"that replaces it, and written down where it is."
                    ),
                    key=key,
                )
            )
        return findings

    # -- plan-level -------------------------------------------------------

    def _drift(self, plan: Plan) -> list[Finding]:
        if not plan.drift:
            return []

        drifted = [rc.address for rc in plan.drift if not rc.is_no_op]
        if not drifted:
            return []

        return [
            self.finding(
                "RD005",
                "State drift: the plan was computed against a stale state",
                Severity.HIGH,
                ", ".join(sorted(drifted)[:5]) + ("..." if len(drifted) > 5 else ""),
                f"Terraform detected that {len(drifted)} resource(s) changed outside of "
                f"Terraform. Every diff in this plan is computed against that stale picture, "
                f"so the plan describes a transition from a state that does not exist.",
                evidence={
                    "drifted_resources": sorted(drifted),
                    "count": len(drifted),
                },
                remediation=(
                    "Refresh and re-plan before approving. Then find who changed these outside "
                    "Terraform, because the same hands will do it again after the apply."
                ),
            )
        ]

    def _scope(self, plan: Plan) -> list[Finding]:
        if not self.claim:
            return []

        unexpected = [
            rc.address
            for rc in plan.effective_changes
            if not any(fnmatch.fnmatch(rc.address, pattern) for pattern in self.claim)
        ]
        if not unexpected:
            return []

        return [
            self.finding(
                "RD007",
                "Plan touches resources outside the declared scope",
                Severity.HIGH,
                ", ".join(sorted(unexpected)[:5]) + ("..." if len(unexpected) > 5 else ""),
                f"The change was declared to touch {', '.join(self.claim)}, but the plan also "
                f"modifies {len(unexpected)} resource(s) that match none of those patterns. "
                f"The gap between the description and the plan is the thing to explain.",
                evidence={
                    "declared_scope": self.claim,
                    "unexpected_resources": sorted(unexpected),
                    "count": len(unexpected),
                },
                remediation=(
                    "Either narrow the change or update its description. A plan that does more "
                    "than the pull request says is how unrelated changes get approved by "
                    "association."
                ),
            )
        ]

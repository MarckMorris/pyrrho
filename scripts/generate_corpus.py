#!/usr/bin/env python3
"""Generate the corpus of infrastructure changes pyrrho is measured against.

Why this is a generator and not 48 hand-written files: the corpus is the
specification, the benchmark input and the regression suite at once, and it has
to stay internally consistent. Declaring each case once and emitting both the
HCL and the plan JSON from that declaration keeps them from drifting apart.

Honesty note, repeated in corpus/README.md and in the project README: the plan
JSON here is written to Terraform's documented plan format (format_version 1.2)
rather than captured from a live `terraform plan` against a real AWS account.
Every case ships the HCL it corresponds to, and scripts/regenerate_from_terraform.sh
regenerates the JSON from real Terraform for anyone who has the binary and
credentials. Cases are marked `verified_against_terraform: false` until that has
been done, and the benchmark prints that flag.

Run:  python scripts/generate_corpus.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "corpus" / "cases"

TERRAFORM_VERSION = "1.9.8"
FORMAT_VERSION = "1.2"
AWS_PROVIDER = "registry.terraform.io/hashicorp/aws"


def rc(
    address: str,
    type_: str,
    actions: list[str],
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    after_unknown: dict[str, Any] | None = None,
    before_sensitive: dict[str, Any] | None = None,
    after_sensitive: dict[str, Any] | None = None,
    action_reason: str | None = None,
    replace_paths: list[list[str]] | None = None,
) -> dict[str, Any]:
    """One entry of resource_changes, in Terraform's documented shape."""
    name = address.split(".")[-1]
    entry: dict[str, Any] = {
        "address": address,
        "mode": "managed",
        "type": type_,
        "name": name,
        "provider_name": AWS_PROVIDER,
        "change": {
            "actions": actions,
            "before": before,
            "after": after,
            "after_unknown": after_unknown or {},
            "before_sensitive": before_sensitive if before_sensitive is not None else False,
            "after_sensitive": after_sensitive if after_sensitive is not None else False,
        },
    }
    if action_reason:
        entry["action_reason"] = action_reason
    if replace_paths:
        entry["change"]["replace_paths"] = replace_paths
    return entry


def sg_rule(
    from_port: int | None,
    to_port: int | None,
    protocol: str,
    cidrs: list[str],
    description: str = "",
    ipv6: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "from_port": from_port,
        "to_port": to_port,
        "protocol": protocol,
        "cidr_blocks": cidrs,
        "ipv6_cidr_blocks": ipv6 or [],
        "prefix_list_ids": [],
        "security_groups": [],
        "self": False,
        "description": description,
    }


def sg(
    name: str,
    ingress: list[dict[str, Any]],
    egress: list[dict[str, Any]] | None = None,
    vpc_id: str = "vpc-0a1b2c3d4e5f60718",
) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"Managed by Terraform: {name}",
        "vpc_id": vpc_id,
        "ingress": ingress,
        "egress": egress if egress is not None else [],
        "tags": {"ManagedBy": "terraform"},
    }


def planned_values(changes: list[dict[str, Any]]) -> dict[str, Any]:
    """The post-apply state, as `terraform show -json` renders it.

    This section is not optional decoration. Most existing scanners read
    ``planned_values`` and ignore ``resource_changes`` entirely, because they
    evaluate the final state against a policy catalogue rather than comparing it
    to the prior state. Emitting only ``resource_changes`` would make this corpus
    unreadable to them, and a benchmark nobody else can run is not a benchmark.

    Resources being destroyed are absent, because after the apply they do not
    exist. That is what real Terraform does too.
    """
    resources: list[dict[str, Any]] = []
    for entry in changes:
        actions = entry["change"]["actions"]
        after = entry["change"].get("after")
        if actions == ["delete"] or actions == ["no-op"] or after is None:
            continue
        resources.append(
            {
                "address": entry["address"],
                "mode": entry.get("mode", "managed"),
                "type": entry["type"],
                "name": entry["name"],
                "provider_name": entry.get("provider_name", AWS_PROVIDER),
                "schema_version": 0,
                "values": after,
                "sensitive_values": entry["change"].get("after_sensitive") or {},
            }
        )
    return {"root_module": {"resources": resources}}


def plan_doc(changes: list[dict[str, Any]], drift: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "terraform_version": TERRAFORM_VERSION,
        "planned_values": planned_values(changes),
        "resource_changes": changes,
        "output_changes": {},
    }
    if drift:
        doc["resource_drift"] = drift
    return doc


# --------------------------------------------------------------------------
# The corpus. Each case: what an engineer would plausibly write, and what it
# would actually do.
# --------------------------------------------------------------------------

CASES: list[dict[str, Any]] = [
    # ---------------- network exposure ----------------
    {
        "id": "ne001-ssh-opened-to-the-internet",
        "title": "Bastion security group opened to 0.0.0.0/0 on SSH",
        "why": (
            "The most common real incident. Someone is locked out, widens the rule to "
            "unblock themselves, and the temporary fix is never reverted."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE001"],
        "forbid": ["NE002"],
        "tf": """
resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = var.vpc_id

  ingress {
    description = "SSH from the office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # was ["203.0.113.0/24"]
  }
}
""",
        "changes": [
            rc(
                "aws_security_group.bastion",
                "aws_security_group",
                ["update"],
                before=sg("bastion", [sg_rule(22, 22, "tcp", ["203.0.113.0/24"], "SSH from the office")]),
                after=sg("bastion", [sg_rule(22, 22, "tcp", ["0.0.0.0/0"], "SSH from the office")]),
            )
        ],
    },
    {
        "id": "ne002-all-ports-all-protocols-from-anywhere",
        "title": "New security group allowing every protocol on every port from anywhere",
        "why": (
            "Written during an outage to rule out the network as a cause, then left in "
            "place because the outage had a different root cause and nobody revisited it."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE002"],
        "forbid": [],
        "tf": """
resource "aws_security_group" "debug" {
  name   = "temp-debug-do-not-merge"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
        "changes": [
            rc(
                "aws_security_group.debug",
                "aws_security_group",
                ["create"],
                before=None,
                after=sg("temp-debug-do-not-merge", [sg_rule(0, 0, "-1", ["0.0.0.0/0"], "")]),
            )
        ],
    },
    {
        "id": "ne003-postgres-exposed-via-modern-rule-resource",
        "title": "PostgreSQL exposed to the internet through aws_vpc_security_group_ingress_rule",
        "why": (
            "The newer singular rule resource uses different attribute names "
            "(cidr_ipv4, ip_protocol). Scanners written against the inline block shape "
            "read it as having no rules at all and report nothing."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE001"],
        "forbid": [],
        "tf": """
resource "aws_vpc_security_group_ingress_rule" "db_from_anywhere" {
  security_group_id = aws_security_group.db.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
  description       = "analytics vendor"
}
""",
        "changes": [
            rc(
                "aws_vpc_security_group_ingress_rule.db_from_anywhere",
                "aws_vpc_security_group_ingress_rule",
                ["create"],
                before=None,
                after={
                    "security_group_id": "sg-0f1e2d3c4b5a69788",
                    "cidr_ipv4": "0.0.0.0/0",
                    "from_port": 5432,
                    "to_port": 5432,
                    "ip_protocol": "tcp",
                    "description": "analytics vendor",
                },
            )
        ],
    },
    {
        "id": "ne004-source-range-widened-to-a-slash-8",
        "title": "MySQL source range widened from a /24 to a /8",
        "why": (
            "The diff shows one string changing and still contains a CIDR, so it reads as "
            "scoped. It admits sixteen million more addresses than it did."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE004"],
        "forbid": ["NE001", "NE002"],
        "tf": """
resource "aws_security_group_rule" "mysql_from_partner" {
  type              = "ingress"
  security_group_id = aws_security_group.db.id
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = ["198.0.0.0/8"] # was ["198.51.100.0/24"]
}
""",
        "changes": [
            rc(
                "aws_security_group_rule.mysql_from_partner",
                "aws_security_group_rule",
                ["update"],
                before={
                    "type": "ingress",
                    "security_group_id": "sg-0f1e2d3c4b5a69788",
                    "from_port": 3306,
                    "to_port": 3306,
                    "protocol": "tcp",
                    "cidr_blocks": ["198.51.100.0/24"],
                    "ipv6_cidr_blocks": [],
                    "description": "partner analytics",
                },
                after={
                    "type": "ingress",
                    "security_group_id": "sg-0f1e2d3c4b5a69788",
                    "from_port": 3306,
                    "to_port": 3306,
                    "protocol": "tcp",
                    "cidr_blocks": ["198.0.0.0/8"],
                    "ipv6_cidr_blocks": [],
                    "description": "partner analytics",
                },
            )
        ],
    },
    {
        "id": "ne005-s3-public-access-guard-disabled",
        "title": "S3 block_public_policy turned off",
        "why": (
            "Disabling the guard exposes nothing by itself, which is exactly why it gets "
            "approved. The bucket policy that makes it matter arrives in a later change."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE005"],
        "forbid": [],
        "tf": """
resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = false # was true
  ignore_public_acls      = true
  restrict_public_buckets = false # was true
}
""",
        "changes": [
            rc(
                "aws_s3_bucket_public_access_block.assets",
                "aws_s3_bucket_public_access_block",
                ["update"],
                before={
                    "bucket": "acme-prod-assets",
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
                after={
                    "bucket": "acme-prod-assets",
                    "block_public_acls": True,
                    "block_public_policy": False,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": False,
                },
            )
        ],
    },
    {
        "id": "ne006-rds-made-publicly-accessible",
        "title": "Production database given a public endpoint",
        "why": (
            "Usually done to let a BI tool or a contractor connect without setting up "
            "peering. The security group becomes the only remaining control."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE006"],
        "forbid": [],
        "tf": """
resource "aws_db_instance" "orders" {
  identifier          = "orders-prod"
  engine              = "postgres"
  publicly_accessible = true # was false
  deletion_protection = true
}
""",
        "changes": [
            rc(
                "aws_db_instance.orders",
                "aws_db_instance",
                ["update"],
                before={
                    "identifier": "orders-prod",
                    "engine": "postgres",
                    "publicly_accessible": False,
                    "deletion_protection": True,
                },
                after={
                    "identifier": "orders-prod",
                    "engine": "postgres",
                    "publicly_accessible": True,
                    "deletion_protection": True,
                },
            )
        ],
    },
    {
        "id": "ne007-internal-load-balancer-made-public",
        "title": "Internal load balancer flipped to internet-facing",
        "why": (
            "A one-character diff, false to true, that changes the reachability of every "
            "target behind the load balancer, including targets added later by other teams."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE007"],
        "forbid": [],
        "tf": """
resource "aws_lb" "internal_api" {
  name     = "internal-api"
  internal = false # was true
  subnets  = var.public_subnets
}
""",
        "changes": [
            rc(
                "aws_lb.internal_api",
                "aws_lb",
                ["update"],
                before={"name": "internal-api", "internal": True, "load_balancer_type": "application"},
                after={"name": "internal-api", "internal": False, "load_balancer_type": "application"},
            )
        ],
    },
    {
        "id": "ne008-network-acl-allow-all-breaks-segmentation",
        "title": "Network ACL entry allowing 0.0.0.0/0 into a private subnet",
        "why": (
            "The network ACL is the subnet's independent boundary and the only control "
            "still standing when a security group is wrong. An allow-all entry removes the "
            "second layer while the first still looks correct."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE008"],
        "forbid": [],
        "tf": """
resource "aws_network_acl_rule" "allow_all_inbound" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
""",
        "changes": [
            rc(
                "aws_network_acl_rule.allow_all_inbound",
                "aws_network_acl_rule",
                ["create"],
                before=None,
                after={
                    "network_acl_id": "acl-0123456789abcdef0",
                    "rule_number": 100,
                    "egress": False,
                    "protocol": "-1",
                    "rule_action": "allow",
                    "cidr_block": "0.0.0.0/0",
                    "from_port": None,
                    "to_port": None,
                },
            )
        ],
    },
    {
        "id": "ne009-unrestricted-egress-added",
        "title": "Unrestricted egress added to a workload security group",
        "why": (
            "Copied from the provider documentation's example block, which uses "
            "0.0.0.0/0 on protocol -1. It is the path data leaves by."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE009"],
        "forbid": ["NE001", "NE002"],
        "tf": """
resource "aws_security_group" "worker" {
  name   = "worker"
  vpc_id = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
        "changes": [
            rc(
                "aws_security_group.worker",
                "aws_security_group",
                ["update"],
                before=sg("worker", [], egress=[]),
                after=sg("worker", [], egress=[sg_rule(0, 0, "-1", ["0.0.0.0/0"], "")]),
            )
        ],
    },
    {
        "id": "ne010-eks-api-server-public",
        "title": "EKS control plane endpoint made public with no allow-list",
        "why": (
            "Enabled to make kubectl work from a laptop. The Kubernetes API is then "
            "internet-reachable with IAM as the only barrier."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE010"],
        "forbid": [],
        "tf": """
resource "aws_eks_cluster" "platform" {
  name = "platform"

  vpc_config {
    endpoint_public_access  = true  # was false
    endpoint_private_access = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}
""",
        "changes": [
            rc(
                "aws_eks_cluster.platform",
                "aws_eks_cluster",
                ["update"],
                before={
                    "name": "platform",
                    "vpc_config": [
                        {
                            "endpoint_public_access": False,
                            "endpoint_private_access": True,
                            "public_access_cidrs": [],
                        }
                    ],
                },
                after={
                    "name": "platform",
                    "vpc_config": [
                        {
                            "endpoint_public_access": True,
                            "endpoint_private_access": True,
                            "public_access_cidrs": ["0.0.0.0/0"],
                        }
                    ],
                },
            )
        ],
    },
    {
        "id": "ne011-private-subnet-starts-assigning-public-ips",
        "title": "Subnet switched to auto-assign public IPs",
        "why": (
            "Changes the character of every instance launched into the subnet from then "
            "on, including instances created by autoscaling long after this review."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE011"],
        "forbid": [],
        "tf": """
resource "aws_subnet" "app" {
  vpc_id                  = var.vpc_id
  cidr_block              = "10.0.12.0/24"
  map_public_ip_on_launch = true # was false
}
""",
        "changes": [
            rc(
                "aws_subnet.app",
                "aws_subnet",
                ["update"],
                before={"cidr_block": "10.0.12.0/24", "map_public_ip_on_launch": False},
                after={"cidr_block": "10.0.12.0/24", "map_public_ip_on_launch": True},
            )
        ],
    },
    {
        "id": "ne012-ingress-rules-unknown-until-apply",
        "title": "Security group whose rules are computed at apply time",
        "why": (
            "The rules come from a module output that Terraform cannot resolve during "
            "plan. A reviewer sees an empty ingress list and approves it. The tool has to "
            "say it cannot review this rather than say it found nothing."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE012"],
        "forbid": ["NE001", "NE002", "NE003"],
        "tf": """
resource "aws_security_group" "dynamic" {
  name   = "dynamic"
  vpc_id = var.vpc_id

  dynamic "ingress" {
    for_each = module.upstream.allowed_rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
}
""",
        "changes": [
            rc(
                "aws_security_group.dynamic",
                "aws_security_group",
                ["create"],
                before=None,
                after={
                    "name": "dynamic",
                    "vpc_id": "vpc-0a1b2c3d4e5f60718",
                    "egress": [],
                    "tags": {},
                },
                after_unknown={"ingress": True, "id": True, "arn": True},
            )
        ],
    },
    {
        "id": "ne013-app-port-exposed-past-the-load-balancer",
        "title": "Application port 8080 opened directly to the internet",
        "why": (
            "Added to debug a load balancer health check. It routes around the load "
            "balancer, and with it TLS termination, the WAF and the access logs. The port "
            "is not a database port, so a rule that only knows about well-known services "
            "says nothing at all."
        ),
        "analyzer": "network-exposure",
        "expect": ["NE003"],
        "forbid": ["NE001", "NE002"],
        "tf": """
resource "aws_security_group" "app" {
  name   = "app"
  vpc_id = var.vpc_id

  ingress {
    description = "direct access for debugging the health check"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
        "changes": [
            rc(
                "aws_security_group.app",
                "aws_security_group",
                ["update"],
                before=sg("app", [sg_rule(8080, 8080, "tcp", ["10.0.0.0/16"], "from the load balancer")]),
                after=sg(
                    "app",
                    [
                        sg_rule(8080, 8080, "tcp", ["10.0.0.0/16"], "from the load balancer"),
                        sg_rule(8080, 8080, "tcp", ["0.0.0.0/0"], "direct access for debugging the health check"),
                    ],
                ),
            )
        ],
    },
    # ---------------- real diff ----------------
    {
        "id": "rd001-production-database-destroyed",
        "title": "Production database destroyed because its block was deleted",
        "why": (
            "A module refactor removes a resource block. Terraform renders one line with "
            "a minus sign, and the data is not in version control."
        ),
        "analyzer": "real-diff",
        "expect": ["RD001"],
        "forbid": ["RD002"],
        "tf": """
# The aws_db_instance.legacy_reports block was removed in this change.
# Terraform reads its absence as an instruction to destroy it.
""",
        "changes": [
            rc(
                "aws_db_instance.legacy_reports",
                "aws_db_instance",
                ["delete"],
                before={
                    "identifier": "legacy-reports-prod",
                    "engine": "postgres",
                    "allocated_storage": 500,
                    "deletion_protection": False,
                    "skip_final_snapshot": True,
                },
                after=None,
                action_reason="delete_because_no_resource_config",
            )
        ],
    },
    {
        "id": "rd002-database-replaced-by-an-immutable-attribute",
        "title": "Database replaced because an immutable attribute changed",
        "why": (
            "Changing the subnet group forces recreation. Terraform shows -/+ and the "
            "reviewer reads it as an update. The new instance comes up empty."
        ),
        "analyzer": "real-diff",
        "expect": ["RD002"],
        "forbid": ["RD001"],
        "tf": """
resource "aws_db_instance" "orders" {
  identifier           = "orders-prod"
  engine               = "postgres"
  db_subnet_group_name = aws_db_subnet_group.new.name # forces replacement
  skip_final_snapshot  = true
}
""",
        "changes": [
            rc(
                "aws_db_instance.orders",
                "aws_db_instance",
                ["delete", "create"],
                before={
                    "identifier": "orders-prod",
                    "engine": "postgres",
                    "db_subnet_group_name": "orders-subnets-old",
                    "skip_final_snapshot": True,
                },
                after={
                    "identifier": "orders-prod",
                    "engine": "postgres",
                    "db_subnet_group_name": "orders-subnets-new",
                    "skip_final_snapshot": True,
                },
                action_reason="replace_because_cannot_update",
                replace_paths=[["db_subnet_group_name"]],
            )
        ],
    },
    {
        "id": "rd003-nat-gateway-replaced-with-downtime",
        "title": "NAT gateway replaced destroy-first, cutting egress for the subnet",
        "why": (
            "Without create_before_destroy there is a window with no NAT gateway. Every "
            "instance in the private subnet loses outbound connectivity for the duration."
        ),
        "analyzer": "real-diff",
        "expect": ["RD003"],
        "forbid": [],
        "tf": """
resource "aws_nat_gateway" "egress" {
  allocation_id = aws_eip.nat_new.id # forces replacement
  subnet_id     = aws_subnet.public.id
  # no lifecycle { create_before_destroy = true }
}
""",
        "changes": [
            rc(
                "aws_nat_gateway.egress",
                "aws_nat_gateway",
                ["delete", "create"],
                before={"allocation_id": "eipalloc-old", "subnet_id": "subnet-0aa"},
                after={"allocation_id": "eipalloc-new", "subnet_id": "subnet-0aa"},
                action_reason="replace_because_cannot_update",
                replace_paths=[["allocation_id"]],
            )
        ],
    },
    {
        "id": "rd004-deletion-protection-and-final-snapshot-removed",
        "title": "Deletion protection disabled and final snapshot skipped in one change",
        "why": (
            "Neither attribute changes anything on apply. Together they remove both "
            "controls that would have stopped, or made recoverable, the next destroy."
        ),
        "analyzer": "real-diff",
        "expect": ["RD004"],
        "forbid": ["RD001", "RD002"],
        "tf": """
resource "aws_db_instance" "orders" {
  identifier          = "orders-prod"
  deletion_protection = false # was true
  skip_final_snapshot = true  # was false
}
""",
        "changes": [
            rc(
                "aws_db_instance.orders",
                "aws_db_instance",
                ["update"],
                before={
                    "identifier": "orders-prod",
                    "deletion_protection": True,
                    "skip_final_snapshot": False,
                },
                after={
                    "identifier": "orders-prod",
                    "deletion_protection": False,
                    "skip_final_snapshot": True,
                },
            )
        ],
    },
    {
        "id": "rd005-plan-computed-against-drifted-state",
        "title": "Plan computed against a state that no longer matches reality",
        "why": (
            "Someone changed the security group in the console. Every diff in this plan "
            "is a diff against a picture that is already wrong, and applying it silently "
            "reverts their change."
        ),
        "analyzer": "real-diff",
        "expect": ["RD005"],
        "forbid": [],
        "tf": """
resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = var.vpc_id
  # Modified outside Terraform since the last apply.
}
""",
        "changes": [
            rc(
                "aws_instance.web",
                "aws_instance",
                ["update"],
                before={"instance_type": "t3.medium", "associate_public_ip_address": False},
                after={"instance_type": "t3.large", "associate_public_ip_address": False},
            )
        ],
        "drift": [
            rc(
                "aws_security_group.web",
                "aws_security_group",
                ["update"],
                before=sg("web", [sg_rule(443, 443, "tcp", ["0.0.0.0/0"], "")]),
                after=sg(
                    "web",
                    [
                        sg_rule(443, 443, "tcp", ["0.0.0.0/0"], ""),
                        sg_rule(22, 22, "tcp", ["0.0.0.0/0"], "added in the console"),
                    ],
                ),
            )
        ],
    },
    {
        "id": "rd006-sensitive-value-rotated-invisibly",
        "title": "Sensitive value changes with the diff redacted",
        "why": (
            "Terraform prints (sensitive value) on both sides. The change is real, "
            "unreviewable from the plan, and anything still holding the old value breaks "
            "at apply."
        ),
        "analyzer": "real-diff",
        "expect": ["RD006"],
        "forbid": [],
        "tf": """
resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id     = aws_secretsmanager_secret.api_key.id
  secret_string = var.new_api_key # sensitive
}
""",
        "changes": [
            rc(
                "aws_secretsmanager_secret_version.api_key",
                "aws_secretsmanager_secret_version",
                ["update"],
                before={"secret_id": "arn:aws:secretsmanager:us-east-1:111122223333:secret:api-key", "secret_string": "REDACTED-OLD"},
                after={"secret_id": "arn:aws:secretsmanager:us-east-1:111122223333:secret:api-key", "secret_string": "REDACTED-NEW"},
                before_sensitive={"secret_string": True},
                after_sensitive={"secret_string": True},
            )
        ],
    },
    {
        "id": "rd007-plan-touches-resources-outside-the-stated-scope",
        "title": "A security group change that also rewrites an IAM role",
        "why": (
            "The pull request says it adjusts a security group. The plan also modifies an "
            "IAM role, which is the kind of thing that gets approved by association with "
            "the change that was actually reviewed."
        ),
        "analyzer": "real-diff",
        "expect": ["RD007"],
        "forbid": [],
        "claim": ["aws_security_group.*"],
        "tf": """
resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = var.vpc_id
}

# Also in this change, not mentioned in the pull request description:
resource "aws_iam_role" "ci_deploy" {
  name               = "ci-deploy"
  assume_role_policy = data.aws_iam_policy_document.ci.json
}
""",
        "changes": [
            rc(
                "aws_security_group.web",
                "aws_security_group",
                ["update"],
                before=sg("web", [sg_rule(443, 443, "tcp", ["10.0.0.0/8"], "")]),
                after=sg("web", [sg_rule(443, 443, "tcp", ["10.0.0.0/8"], "internal only")]),
            ),
            rc(
                "aws_iam_role.ci_deploy",
                "aws_iam_role",
                ["update"],
                before={"name": "ci-deploy", "max_session_duration": 3600},
                after={"name": "ci-deploy", "max_session_duration": 43200},
            ),
        ],
    },
    {
        "id": "rd008-bucket-policy-unknown-until-apply",
        "title": "Bucket policy that Terraform cannot resolve before apply",
        "why": (
            "The policy is rendered from a data source that resolves at apply time. "
            "Approving the plan approves a policy document nobody has read."
        ),
        "analyzer": "real-diff",
        "expect": ["RD008"],
        "forbid": [],
        "tf": """
resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = data.aws_iam_policy_document.assets.json # known after apply
}
""",
        "changes": [
            rc(
                "aws_s3_bucket_policy.assets",
                "aws_s3_bucket_policy",
                ["update"],
                before={"bucket": "acme-prod-assets", "policy": "{\"Version\":\"2012-10-17\"}"},
                after={"bucket": "acme-prod-assets"},
                after_unknown={"policy": True},
            )
        ],
    },
    {
        "id": "rd009-kms-key-destroyed-with-encrypted-data-behind-it",
        "title": "KMS key destroyed while data encrypted under it remains",
        "why": (
            "Deleting the key is a single line. Everything encrypted with it becomes "
            "permanently unreadable, including backups taken before the change."
        ),
        "analyzer": "real-diff",
        "expect": ["RD001"],
        "forbid": [],
        "tf": """
# The aws_kms_key.backups block was removed during a cleanup of unused resources.
""",
        "changes": [
            rc(
                "aws_kms_key.backups",
                "aws_kms_key",
                ["delete"],
                before={
                    "description": "encrypts nightly backups",
                    "deletion_window_in_days": 7,
                    "enable_key_rotation": True,
                },
                after=None,
                action_reason="delete_because_no_resource_config",
            )
        ],
    },
    {
        "id": "rd010-log-group-replaced-losing-the-audit-trail",
        "title": "CloudWatch log group replaced, discarding retained events",
        "why": (
            "Renaming a log group replaces it. The retained events go with the old one, "
            "which matters most in exactly the situation you need them for."
        ),
        "analyzer": "real-diff",
        "expect": ["RD002"],
        "forbid": [],
        "tf": """
resource "aws_cloudwatch_log_group" "audit" {
  name              = "/acme/audit-v2" # was "/acme/audit", forces replacement
  retention_in_days = 365
}
""",
        "changes": [
            rc(
                "aws_cloudwatch_log_group.audit",
                "aws_cloudwatch_log_group",
                ["delete", "create"],
                before={"name": "/acme/audit", "retention_in_days": 365},
                after={"name": "/acme/audit-v2", "retention_in_days": 365},
                action_reason="replace_because_cannot_update",
                replace_paths=[["name"]],
            )
        ],
    },
    # ---------------- negative controls ----------------
    {
        "id": "nc001-https-served-to-the-public-on-purpose",
        "title": "A public web server serving 443 to the internet",
        "why": (
            "This is what a correct public service looks like. A tool that calls this "
            "critical is a tool people turn off."
        ),
        "analyzer": "network-exposure",
        "benign": True,
        "expect": [],
        "forbid": ["NE001", "NE002", "NE004"],
        "max_severity": "low",
        "tf": """
resource "aws_security_group" "public_web" {
  name   = "public-web"
  vpc_id = var.vpc_id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
        "changes": [
            rc(
                "aws_security_group.public_web",
                "aws_security_group",
                ["create"],
                before=None,
                after=sg("public-web", [sg_rule(443, 443, "tcp", ["0.0.0.0/0"], "HTTPS from the internet")]),
            )
        ],
    },
    {
        "id": "nc002-preexisting-exposure-left-untouched",
        "title": "A tag change on a security group that was already open to the world",
        "why": (
            "The single most important negative control. The exposure is real but it is "
            "not this change's doing. A tool that blocks this pull request is blocking the "
            "wrong pull request, and teaches the team that its findings are noise."
        ),
        "analyzer": "network-exposure",
        "benign": True,
        "expect": [],
        "forbid": ["NE001", "NE002", "NE003", "NE004"],
        "tf": """
resource "aws_security_group" "legacy" {
  name   = "legacy"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # unchanged, pre-existing
  }

  tags = { Owner = "platform" } # the only thing this change does
}
""",
        "changes": [
            rc(
                "aws_security_group.legacy",
                "aws_security_group",
                ["update"],
                before={
                    **sg("legacy", [sg_rule(22, 22, "tcp", ["0.0.0.0/0"], "")]),
                    "tags": {"ManagedBy": "terraform"},
                },
                after={
                    **sg("legacy", [sg_rule(22, 22, "tcp", ["0.0.0.0/0"], "")]),
                    "tags": {"ManagedBy": "terraform", "Owner": "platform"},
                },
            )
        ],
    },
    {
        "id": "nc003-source-range-narrowed",
        "title": "An SSH rule narrowed from the internet to the VPN range",
        "why": (
            "A strict improvement. Reporting it would mean the tool cannot tell the "
            "direction of a change, only that one happened."
        ),
        "analyzer": "network-exposure",
        "benign": True,
        "expect": [],
        "forbid": ["NE001", "NE002", "NE003", "NE004"],
        "tf": """
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.bastion.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.20.0.0/16"] # was ["0.0.0.0/0"]
}
""",
        "changes": [
            rc(
                "aws_security_group_rule.ssh",
                "aws_security_group_rule",
                ["update"],
                before={
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": [],
                },
                after={
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.20.0.0/16"],
                    "ipv6_cidr_blocks": [],
                },
            )
        ],
    },
    {
        "id": "nc004-stateless-resource-replaced",
        "title": "A launch template replaced, which loses nothing",
        "why": (
            "Replacement is only alarming when something irreplaceable goes with it. "
            "Treating every -/+ as critical is how a tool becomes background noise."
        ),
        "analyzer": "real-diff",
        "benign": True,
        "expect": [],
        "forbid": ["RD001", "RD002", "RD003"],
        "tf": """
resource "aws_launch_template" "workers" {
  name_prefix   = "workers-"
  image_id      = data.aws_ami.al2023.id # forces a new version
  instance_type = "m6i.large"
}
""",
        "changes": [
            rc(
                "aws_launch_template.workers",
                "aws_launch_template",
                ["delete", "create"],
                before={"name_prefix": "workers-", "image_id": "ami-old", "instance_type": "m6i.large"},
                after={"name_prefix": "workers-", "image_id": "ami-new", "instance_type": "m6i.large"},
                action_reason="replace_because_cannot_update",
                replace_paths=[["image_id"]],
            )
        ],
    },
]


def main() -> int:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []

    for case in CASES:
        case_dir = CASES_DIR / case["id"]
        case_dir.mkdir(parents=True, exist_ok=True)

        (case_dir / "main.tf").write_text(case["tf"].strip() + "\n", encoding="utf-8")

        doc = plan_doc(case["changes"], case.get("drift"))
        (case_dir / "plan.json").write_text(
            json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )

        manifest.append(
            {
                "id": case["id"],
                "title": case["title"],
                "why": " ".join(case["why"].split()),
                "analyzer": case["analyzer"],
                "benign": bool(case.get("benign", False)),
                "expect": case["expect"],
                "forbid": case["forbid"],
                "claim": case.get("claim", []),
                "max_severity": case.get("max_severity"),
                "plan": f"cases/{case['id']}/plan.json",
                "terraform": f"cases/{case['id']}/main.tf",
                "verified_against_terraform": False,
            }
        )

    dangerous = [c for c in manifest if not c["benign"]]
    controls = [c for c in manifest if c["benign"]]

    (ROOT / "corpus" / "manifest.json").write_text(
        json.dumps(
            {
                "format": "pyrrho-corpus/v1",
                "terraform_version": TERRAFORM_VERSION,
                "plan_format_version": FORMAT_VERSION,
                "counts": {
                    "total": len(manifest),
                    "dangerous": len(dangerous),
                    "benign_controls": len(controls),
                },
                "cases": manifest,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"wrote {len(dangerous)} dangerous cases and {len(controls)} negative controls")
    print(f"  {CASES_DIR}")
    print(f"  {ROOT / 'corpus' / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

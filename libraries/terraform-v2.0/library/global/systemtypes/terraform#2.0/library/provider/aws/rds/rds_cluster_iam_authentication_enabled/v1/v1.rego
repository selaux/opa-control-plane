package global.systemtypes["terraform:2.0"].library.provider.aws.rds.rds_cluster_iam_authentication_enabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: RDS: Prohibit RDS clusters with disabled IAM authentication"
# description: Require AWS/RDS clusters to have IAM authentication enabled.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-rds"
# custom:
#   id: "aws.rds.rds_cluster_iam_authentication_enabled"
#   impact: ""
#   remediation: ""
#   severity: "medium"
#   resource_category: ""
#   control_category: ""
#   rule_link: "https://docs.styra.com/systems/terraform/snippets"
#   platform:
#     name: "terraform"
#     versions:
#       min: "v0.12"
#       max: "v1.3"
#   provider:
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - { scope: "resource", service: "rds", name: "rds_cluster", identifier: "aws_rds_cluster", argument: "iam_database_authentication_enabled" }
# schema:
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "violation.message"
#     - type: rego
#       key: metadata
#       value: "violation.metadata"
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[violation]"
prohibit_rds_clusters_with_disabled_iam_authentication[violation] {
	insecure_rds[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_rds[obj] {
	rds_cluster := util.rds_cluster_resource_changes[_]
	rds_cluster.change.after.iam_database_authentication_enabled == false

	obj := {
		"message": sprintf("RDS cluster %v with disabled IAM authentication is prohibited.", [rds_cluster.address]),
		"resource": rds_cluster,
		"context": {"iam_database_authentication_enabled": rds_cluster.change.after.iam_database_authentication_enabled},
	}
}

insecure_rds[obj] {
	rds_cluster := util.rds_cluster_resource_changes[_]
	rds_cluster.change.after.iam_database_authentication_enabled == null

	obj := {
		"message": sprintf("IAM authentication for RDS cluster %v is not configured.", [rds_cluster.address]),
		"resource": rds_cluster,
		"context": {"iam_database_authentication_enabled": rds_cluster.change.after.iam_database_authentication_enabled},
	}
}

insecure_rds[obj] {
	rds_cluster := util.rds_cluster_resource_changes[_]
	not utils.is_key_defined(rds_cluster.change.after, "iam_database_authentication_enabled")

	obj := {
		"message": sprintf("IAM authentication for RDS cluster %v is not configured.", [rds_cluster.address]),
		"resource": rds_cluster,
		"context": {"iam_database_authentication_enabled": "undefined"},
	}
}

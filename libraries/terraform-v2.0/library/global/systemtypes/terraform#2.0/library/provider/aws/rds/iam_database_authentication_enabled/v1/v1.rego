package global.systemtypes["terraform:2.0"].library.provider.aws.rds.iam_database_authentication_enabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: RDS: Prohibit RDS instances with disabled IAM database authentication"
# description: Require AWS/RDS instances to have IAM authentication enabled.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-rds"
# custom:
#   id: "aws.rds.iam_database_authentication_enabled"
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
#     - { scope: "resource", service: "rds", name: "db_instance", identifier: "aws_db_instance", argument: "iam_database_authentication_enabled" }
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
prohibit_rds_instance_with_disabled_iam_authentication[violation] {
	insecure_rds[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_rds[obj] {
	rds_instance := util.db_instance_resource_changes[_]
	rds_instance.change.after.iam_database_authentication_enabled == false

	obj := {
		"message": sprintf("RDS instance %v with disabled IAM database authentication is prohibited.", [rds_instance.address]),
		"resource": rds_instance,
		"context": {"iam_database_authentication_enabled": rds_instance.change.after.iam_database_authentication_enabled},
	}
}

insecure_rds[obj] {
	rds_instance := util.db_instance_resource_changes[_]
	rds_instance.change.after.iam_database_authentication_enabled == null

	obj := {
		"message": sprintf("IAM database authentication for RDS instance %v is not configured.", [rds_instance.address]),
		"resource": rds_instance,
		"context": {"iam_database_authentication_enabled": rds_instance.change.after.iam_database_authentication_enabled},
	}
}

insecure_rds[obj] {
	rds_instance := util.db_instance_resource_changes[_]
	not utils.is_key_defined(rds_instance.change.after, "iam_database_authentication_enabled")

	obj := {
		"message": sprintf("IAM database authentication for RDS instance %v is not configured.", [rds_instance.address]),
		"resource": rds_instance,
		"context": {"iam_database_authentication_enabled": "undefined"},
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.rds.publicly_accessible.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: RDS: Prohibit publicly accessible RDS instances"
# description: Require AWS/RDS instances to not be publicly accessible.
# severity: "high"
# platform: "terraform"
# resource-type: "aws-rds"
# custom:
#   id: "aws.rds.publicly_accessible"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
#     - { scope: "resource", service: "rds", name: "db_instance", identifier: "aws_db_instance", argument: "publicly_accessible" }
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
prohibit_publicly_accessible_db_instance[violation] {
	insecure_rds_instance[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_rds_instance[obj] {
	rds_instance := util.db_instance_resource_changes[_]
	rds_instance.change.after.publicly_accessible == true

	obj := {
		"message": sprintf("Publicly accessible RDS instance %v is prohibited.", [rds_instance.address]),
		"resource": rds_instance,
		"context": {"publicly_accessible": rds_instance.change.after.publicly_accessible},
	}
}

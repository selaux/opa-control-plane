package global.systemtypes["terraform:2.0"].library.provider.aws.rds.automatic_minor_version_upgrade_enabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: RDS: Prohibit RDS instance with disabled automatic minor version upgrade"
# description: Require AWS/RDS instances to have automatic minor version upgrade enabled.
# severity: "high"
# platform: "terraform"
# resource-type: "aws-rds"
# custom:
#   id: "aws.rds.automatic_minor_version_upgrade_enabled"
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
#     - { scope: "resource", service: "rds", name: "db_instance", identifier: "aws_db_instance", argument: "auto_minor_version_upgrade" }
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
enable_auto_minor_version_upgrade_rds_instance[violation] {
	auto_minor_version_upgrade_check_rds[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

auto_minor_version_upgrade_check_rds[obj] {
	rds_instance := util.db_instance_resource_changes[_]
	rds_instance.change.after.auto_minor_version_upgrade == false

	obj := {
		"message": sprintf("Automatic minor version upgrade on RDS instance %v is disabled.", [rds_instance.address]),
		"resource": rds_instance,
		"context": {"auto_minor_version_upgrade": false},
	}
}

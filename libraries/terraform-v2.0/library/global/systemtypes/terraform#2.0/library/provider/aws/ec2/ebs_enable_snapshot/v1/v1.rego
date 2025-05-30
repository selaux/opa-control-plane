package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.ebs_enable_snapshot.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2/EBS: Requires volumes to have a snapshot."
# description: Ensure individually created EBS volumes have at least one associated snapshot.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2/ebs"
# custom:
#   id: "aws.ec2.ebs_enable_snapshot"
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
#     - { scope: "resource", service: "ebs", name: "ebs_volume", identifier: "aws_ebs_volume" }
#     - { scope: "resource", service: "ebs", name: "ebs_snapshot", identifier: "aws_ebs_snapshot", argument: "volume_id" }
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
ec2_ebs_enable_snapshot[violation] {
	ebs_enable_snapshot[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

ebs_enable_snapshot[obj] {
	ebs := util.ebs_volume_resource_changes[_]

	not ebs_snapshot_resource_present(utils.module_type(ebs))

	obj := {
		"message": sprintf("EBS volume %v requires snapshot enabled.", [ebs.address]),
		"resource": ebs,
		"context": {"ebs_snapshot": "undefined"},
	}
}

ebs_snapshot_resource_present(ebs_volume_module) {
	ebs_snapshot_resource := util.ebs_snapshot_resource_changes[_]
	ebs_snapshot_module := utils.module_type(ebs_snapshot_resource)
	ebs_snapshot_module == ebs_volume_module
}

ebs_enable_snapshot[obj] {
	ebs := util.ebs_volume_resource_changes[_]
	ebs_volume_module := utils.module_type(ebs)

	ebs_snapshot_configuration_block := util.ebs_snapshot_conf_resources
	ebs_volume_configuration_address := concat("", ["aws_ebs_volume.", ebs.name])
	not is_reference_to_ebs_volume_present(ebs_volume_configuration_address, ebs_snapshot_configuration_block, ebs_volume_module)

	obj := {
		"message": sprintf("EBS volume %v requires snapshot enabled.", [ebs.address]),
		"resource": ebs,
		"context": {"ebs_snapshot": "undefined"},
	}
}

is_reference_to_ebs_volume_present(ebs_volume_configuration_address, ebs_snapshot_configuration_blocks, ebs_volume_module) {
	ebs_snapshot_block := ebs_snapshot_configuration_blocks[_]
	utils.module_type(ebs_snapshot_block) == ebs_volume_module
	ebs_volume_configuration_address == ebs_snapshot_configuration_blocks[_].expressions.volume_id.references[_]
}

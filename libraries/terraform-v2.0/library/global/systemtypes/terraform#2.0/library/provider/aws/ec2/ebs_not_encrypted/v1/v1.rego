package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.ebs_not_encrypted.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Ensure the EBS volumes are encrypted"
# description: Require individually created EBS volumes to be encrypted.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.ebs_not_encrypted"
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
#     - { scope: "resource", service: "ebs", name: "ebs_volume", identifier: "aws_ebs_volume", argument: "encrypted" }
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
ebs_not_encrypted[violation] {
	ebs_volume_not_encrypted[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

ebs_volume_not_encrypted[obj] {
	ebs := util.ebs_volume_resource_changes[_]
	ebs.change.after.encrypted == false

	obj := {
		"message": sprintf("EBS volume %v is not encrypted.", [ebs.address]),
		"resource": ebs,
		"context": {"encrypted": false},
	}
}

ebs_volume_not_encrypted[obj] {
	ebs := util.ebs_volume_resource_changes[_]
	not utils.is_key_defined(ebs.change.after, "encrypted")

	obj := {
		"message": sprintf("EBS volume %v without encyption defined is prohibited.", [ebs.address]),
		"resource": ebs,
		"context": {"encrypted": "undefined"},
	}
}

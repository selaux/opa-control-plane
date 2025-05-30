package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.without_encrypted_volume.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Ensure the instances use encrypted volume."
# description: Require AWS/EC2 instances to use encrypted block storage volume.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.without_encrypted_volume"
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
#     - { scope: "resource", service: "ec2", "name": "instance", identifier: "aws_instance", argument: "ebs_block_device.encrypted" }
#     - { scope: "resource", service: "ec2", "name": "instance", identifier: "aws_instance", argument: "root_block_device.encrypted" }
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
ec2_without_encrypted_volume[violation] {
	without_encrypted_volume[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

without_encrypted_volume[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	ebs_volume := ec2_instance.change.after.ebs_block_device[_]
	ebs_volume.encrypted == false

	obj := {
		"message": sprintf("EC2 instance %v has unencrypted ebs block storage volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"ebs_volume.encrypted": false},
	}
}

without_encrypted_volume[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	root_volume := ec2_instance.change.after.root_block_device[_]
	root_volume.encrypted == false

	obj := {
		"message": sprintf("EC2 instance %v has unencrypted root block storage volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"root_volume.encrypted": false},
	}
}

without_encrypted_volume[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	ebs_volume := ec2_instance.change.after.ebs_block_device[_]
	not utils.is_key_defined(ebs_volume, "encrypted")

	obj := {
		"message": sprintf("EC2 instance %v does not have encryption configured for ebs block storage volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"ebs_volume.encrypted": "undefined"},
	}
}

without_encrypted_volume[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	root_volume := ec2_instance.change.after.root_block_device[_]
	not utils.is_key_defined(root_volume, "encrypted")

	obj := {
		"message": sprintf("EC2 instance %v does not have encryption configured for root block storage volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"root_volume.encrypted": "undefined"},
	}
}

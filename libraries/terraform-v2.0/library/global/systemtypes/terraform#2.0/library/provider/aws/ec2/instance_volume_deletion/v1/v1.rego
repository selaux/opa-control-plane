package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.instance_volume_deletion.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Restrict volume deletion after instance termination"
# description: Prevent volume being deleted after the termination of EC2 instance.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.instance_volume_deletion"
#   impact: "Retaining volumes until they are explicitly deleted can protect against adversaries deleting critical data or evidence of an intrusion."
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
#     - { scope: "resource", service: "ec2", "name": "instance", identifier: "aws_instance", argument: "ebs_block_device.delete_on_termination" }
#     - { scope: "resource", service: "ec2", "name": "instance", identifier: "aws_instance", argument: "root_block_device.delete_on_termination" }
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
volume_deletion[violation] {
	ec2_volume_deletion[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

ec2_volume_deletion[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	ebs_volume := ec2_instance.change.after.ebs_block_device[_]
	ebs_volume.delete_on_termination == true

	obj := {
		"message": sprintf("EC2 instance %v has 'delete_on_termination' enabled for EBS volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"ebs_block_device.delete_on_termination": true},
	}
}

ec2_volume_deletion[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	ebs_volume := ec2_instance.change.after.ebs_block_device[_]
	not utils.is_key_defined(ebs_volume, "delete_on_termination")

	obj := {
		"message": sprintf("EC2 instance %v does not have 'delete_on_termination' configured for EBS volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"ebs_block_device.delete_on_termination": "undefined"},
	}
}

ec2_volume_deletion[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	root_volume := ec2_instance.change.after.root_block_device[_]
	root_volume.delete_on_termination == true

	obj := {
		"message": sprintf("EC2 instance %v has 'delete_on_termination' enabled for root EBS volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"root_block_device.delete_on_termination": true},
	}
}

ec2_volume_deletion[obj] {
	ec2_instance := util.ec2_instance_resource_changes[_]
	root_volume := ec2_instance.change.after.root_block_device[_]
	not utils.is_key_defined(root_volume, "delete_on_termination")

	obj := {
		"message": sprintf("EC2 instance %v does not have 'delete_on_termination' configured for root EBS volume.", [ec2_instance.address]),
		"resource": ec2_instance,
		"context": {"root_block_device.delete_on_termination": "undefined"},
	}
}

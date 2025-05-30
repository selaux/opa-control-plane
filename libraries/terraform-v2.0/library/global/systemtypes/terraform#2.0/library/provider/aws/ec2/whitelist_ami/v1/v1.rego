package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.whitelist_ami.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import data.library.parameters
import future.keywords.in

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Restrict instances with unapproved AMIs"
# description: Require EC2 instances to use an AMI from a pre-approved list.
# severity: "high"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.whitelist_ami"
#   impact: "Running an unapproved AMI may result in using vulnerable images."
#   remediation: "Launch instances using only AMI images defined in the pre-approved list."
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
#     - { scope: "resource", service: "ec2", name: "instance", identifier: "aws_instance", argument: "ami" }
#     - { scope: "resource", service: "ec2", name: "launch_template", identifier: "aws_launch_template", argument: "image_id" }
#     - { scope: "resource", service: "autoscaling_group", "name": "launch_configuration", identifier: "aws_launch_configuration", argument: "image_id" }
# schema:
#   parameters:
#     - name: allowed_ami_ids
#       label: "A list of AMI IDs (e.g., ami-830c94e3, ami-0022c769)"
#       type: set_of_strings
#       required: true
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
ec2_whitelist_amis[violation] {
	ami_resources[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), parameters, decision.resource, decision.context),
	}
}

ami_resources[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	ami_id := ec2.change.after.ami
	not ami_id in parameters.allowed_ami_ids

	obj := {
		"message": sprintf("EC2 instance %v uses an unapproved AMI ID %v.", [ec2.address, ami_id]),
		"resource": ec2,
		"context": {"ami": ami_id},
	}
}

ami_resources[obj] {
	template := util.launch_template_resource_changes[_]
	ami_id := template.change.after.image_id
	not ami_id in parameters.allowed_ami_ids

	obj := {
		"message": sprintf("Launch template %v uses an unapproved AMI image ID %v.", [template.address, ami_id]),
		"resource": template,
		"context": {"ami": ami_id},
	}
}

ami_resources[obj] {
	configuration := util.launch_configuration_resource_changes[_]
	ami_id := configuration.change.after.image_id
	not ami_id in parameters.allowed_ami_ids

	obj := {
		"message": sprintf("Launch configuration %v uses an unapproved AMI image ID %v.", [configuration.address, ami_id]),
		"resource": configuration,
		"context": {"ami": ami_id},
	}
}

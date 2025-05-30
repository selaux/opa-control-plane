package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.whitelisted_security_groups.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import data.library.parameters

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Restrict instances with unapproved Security Groups"
# description: Require AWS/EC2 to use Security Groups from a pre-approved list.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.whitelisted_security_groups"
#   impact: ""
#   remediation: ""
#   severity: ""
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
#     - { scope: "resource", service: "ec2", name: "instance", identifier: "aws_instance", argument: "vpc_security_group_ids" }
# schema:
#   parameters:
#     - name: allowed_security_groups
#       label: "A list of Security Groups (e.g., sg-830c94e3, sg-0022c769)"
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
ec2_whitelist_security_groups[violation] {
	ec2_resources[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), parameters, decision.resource, decision.context),
	}
}

ec2_resources[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	not utils.is_key_defined(ec2.change.after, "vpc_security_group_ids")

	obj := {
		"message": sprintf("EC2 instance %v does not have a VPC security group specified.", [ec2.address]),
		"resource": ec2,
		"context": {"vpc_security_group_ids": "undefined"},
	}
}

ec2_resources[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	security_group_id := ec2.change.after.vpc_security_group_ids[_]
	not utils.is_element_present(parameters.allowed_security_groups, security_group_id)

	obj := {
		"message": sprintf("EC2 instance %v uses an unapproved VPC security group id %v.", [ec2.address, security_group_id]),
		"resource": ec2,
		"context": {"vpc_security_group_id": security_group_id},
	}
}

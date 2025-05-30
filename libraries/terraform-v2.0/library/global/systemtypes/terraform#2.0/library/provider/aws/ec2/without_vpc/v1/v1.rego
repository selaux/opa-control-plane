package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.without_vpc.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Prohibit EC2 instances without a VPC"
# description: >-
#   Require AWS/EC2 instances to be deployed in a dedicated VPC with specified security group IDs
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.without_vpc"
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
#     - { scope: "resource", service: "ec2", name: "instance", identifier: "aws_instance", argument: "vpc_security_group_ids" }
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
ec2_outside_vpc[violation] {
	ec2_resources[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

ec2_resources[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	not ec2.change.after.vpc_security_group_ids

	obj := {
		"message": sprintf("EC2 instance %v does not define associated VPC security group IDs.", [ec2.address]),
		"resource": ec2,
		"context": {"vpc_security_group_ids": "undefined"},
	}
}

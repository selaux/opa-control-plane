package global.systemtypes["terraform:2.0"].library.provider.aws.autoscaling.launch_configuration_public_ip_disabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: AutoScaling Group: Deny public IP address in launch configuration"
# description: Prohibit creation of autoscaling group if the launch configuration used has public IP address enabled.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-autoscaling_group"
# custom:
#   id: "aws.autoscaling.launch_configuration_public_ip_disabled"
#   impact: "Using Public IP in ASG Launch Configuration can increase the attack surface."
#   remediation: "Do not associate public IP address to ASG Launch Configuration."
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
#     - { scope: "resource", service: "autoscaling_group", "name": "launch_configuration", identifier: "aws_launch_configuration", argument: "associate_public_ip_address" }
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
prohibit_public_ip_launch_config[violation] {
	launch_config_public_ip_disabled[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

launch_config_public_ip_disabled[obj] {
	asg_launch_configuration := util.launch_configuration_resource_changes[_]
	asg_launch_configuration.change.after.associate_public_ip_address == true

	obj := {
		"message": sprintf("AWS launch configuration %v with an associated public IP address is prohibited", [asg_launch_configuration.address]),
		"resource": asg_launch_configuration,
		"context": {"associate_public_ip_address": asg_launch_configuration.change.after.associate_public_ip_address},
	}
}

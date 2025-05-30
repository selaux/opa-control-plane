package global.systemtypes["terraform:2.0"].library.provider.aws.ecs.service_with_no_public_ip.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: ECS: Prohibit ECS Service which has Assign Public IP enabled"
# description: Require AWS/ECS Service to have 'assign_public_ip' set as false in 'network_configuration'.
# severity: "high"
# platform: "terraform"
# resource-type: "aws-ecs_service"
# custom:
#   id: "aws.ecs.service_with_no_public_ip"
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
#     - { scope: "resource", service: "ecs", "name": "ecs_service", identifier: "aws_ecs_service", argument: "network_configuration.assign_public_ip" }
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
prohibit_ecs_service_with_public_ip_set_as_true[violation] {
	insecure_ecs_service[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_ecs_service[obj] {
	ecs_service := util.ecs_service_resource_changes[_]
	assign_public_ip := ecs_service.change.after.network_configuration[_].assign_public_ip
	assign_public_ip == true

	obj := {
		"message": sprintf("AWS ECS Service %v with 'assign_public_ip' set as true in 'network_configuration' is prohibited.", [ecs_service.address]),
		"resource": ecs_service,
		"context": {"assign_public_ip": assign_public_ip},
	}
}

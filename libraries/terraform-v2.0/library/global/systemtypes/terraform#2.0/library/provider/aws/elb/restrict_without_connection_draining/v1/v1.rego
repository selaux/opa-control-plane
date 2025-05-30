package global.systemtypes["terraform:2.0"].library.provider.aws.elb.restrict_without_connection_draining.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: ELB: Prohibit Elastic Load Balancers with connection draining not set to true"
# description: Requires AWS/ELB listeners to be configured with connection_draining as true.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-elb"
# custom:
#   id: "aws.elb.restrict_without_connection_draining"
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
#     - { scope: "resource", service: "elb", name: "elb", identifier: "aws_elb", argument: "connection_draining" }
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
prohibit_elastic_load_balancer_without_connection_draining_set_to_true[violation] {
	restrict_elb_without_connection_draining_set_to_true[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

restrict_elb_without_connection_draining_set_to_true[obj] {
	elb := util.elb_resource_changes[_]
	elb.change.after.connection_draining == false

	obj := {
		"message": sprintf("Elastic Load Balancer %v without 'connection_draining' set to true is prohibited.", [elb.address]),
		"resource": elb,
		"context": {"connection_draining": elb.change.after.connection_draining},
	}
}

restrict_elb_without_connection_draining_set_to_true[obj] {
	elb := util.elb_resource_changes[_]
	not utils.is_key_defined(elb.change.after, "connection_draining")

	obj := {
		"message": sprintf("Elastic Load Balancer %v without 'connection_draining' defined is prohibited.", [elb.address]),
		"resource": elb,
		"context": {"connection_draining": "undefined"},
	}
}

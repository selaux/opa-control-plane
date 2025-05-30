package global.systemtypes["terraform:2.0"].library.provider.aws.elb.restrict_listener_without_ssl_or_https.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: ELB: Prohibit Elastic Load Balancers with listener's lb_protocol not set to SSL/HTTPS"
# description: Requires AWS/ELB listeners to be configured with lb_protocol as either SSL or HTTPS.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-elb"
# custom:
#   id: "aws.elb.restrict_listener_without_ssl_or_https"
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
#     - { scope: "resource", service: "elb", name: "elb", identifier: "aws_elb", argument: "listener.lb_protocol" }
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
prohibit_elastic_load_balancer_without_lb_protocol_ssl_or_https[violation] {
	restrict_listener_without_ssl_or_https[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

restrict_listener_without_ssl_or_https[obj] {
	secure_lb_protocols := ["ssl", "https"]
	elb := util.elb_resource_changes[_]
	lb_protocol := elb.change.after.listener[_].lb_protocol
	not utils.is_element_present(secure_lb_protocols, lb_protocol)

	obj := {
		"message": sprintf("Elastic Load Balancer %v listener(s) without SSL or HTTPS 'lb_protocol' is prohibited.", [elb.address]),
		"resource": elb,
		"context": {"listener.lb_protocol": lb_protocol},
	}
}

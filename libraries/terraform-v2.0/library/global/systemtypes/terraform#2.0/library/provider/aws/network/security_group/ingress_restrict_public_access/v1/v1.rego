package global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.ingress_restrict_public_access.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Security Groups: Restrict Ingress from public IPs."
# description: Require AWS/Security Groups to allow ingress from private IPv4 CIDRs only. Private IPv4 CIDR IP 'ranges:' "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-security_groups"
# custom:
#   id: "aws.network.security_group.ingress_restrict_public_access"
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
#     - { scope: "resource", service: "vpc", name: "security_group", identifier: "aws_security_group", argument: "ingress.cidr_blocks" }
#     - { scope: "resource", service: "vpc", name: "security_group_rule", identifier: "aws_security_group_rule", argument: "cidr_blocks" }
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
ingress_restrict_public_access[violation] {
	insecure_ingress_rule[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

# The whitelist_cidr is a list of private IP CIDRs, so any IP or CIDR which does not come under
# this list of IPs, will be blocked by the rule.
whitelist_cidrs := ["10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"]

insecure_ingress_rule[obj] {
	sg_resource := util.security_group_resource_changes[_]
	ing := sg_resource.change.after.ingress[_]
	cidr := ing.cidr_blocks[_]
	not cidr_allowed(cidr)

	obj := {
		"message": sprintf("Security Group %v has an unapproved ingress from 'cidr:' %v.", [sg_resource.address, cidr]),
		"resource": sg_resource,
		"context": {"ingress.cidr_blocks": cidr},
	}
}

insecure_ingress_rule[obj] {
	sg_rule_resource := util.security_group_rule_resource_changes[_]
	sg_rule_resource.change.after.type == "ingress"
	cidr := sg_rule_resource.change.after.cidr_blocks[_]
	not cidr_allowed(cidr)

	obj := {
		"message": sprintf("Security Group Rule %v has an unapproved ingress from 'cidr:' %v.", [sg_rule_resource.address, cidr]),
		"resource": sg_rule_resource,
		"context": {"cidr_blocks": cidr},
	}
}

cidr_allowed(cidr) {
	valid_cidr := whitelist_cidrs[_]
	net.cidr_contains(valid_cidr, cidr)
}

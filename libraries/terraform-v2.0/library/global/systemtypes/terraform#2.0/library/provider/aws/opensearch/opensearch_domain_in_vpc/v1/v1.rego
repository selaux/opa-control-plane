package global.systemtypes["terraform:2.0"].library.provider.aws.opensearch.opensearch_domain_in_vpc.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Opensearch: Prohibit Opensearch Domains not created in VPC"
# description: Require AWS/Opensearch domains to have subnets added in vpc_options.
# severity: "critical"
# platform: "terraform"
# resource-type: "aws-opensearch"
# custom:
#   id: "aws.opensearch.opensearch_domain_in_vpc"
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
#     - { scope: "resource", service: "opensearch", "name": "opensearch_domain", identifier: "aws_opensearch_domain", argument: "vpc_options.subnet_ids" }
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
prohibit_opensearch_domains_not_in_vpc[violation] {
	opensearch_domain_not_in_vpc[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

opensearch_domain_not_in_vpc[obj] {
	os_domain := util.opensearch_domain_resource_changes[_]
	not utils.is_key_defined(os_domain.change.after, "vpc_options")

	obj := {
		"message": sprintf("AWS Opensearch domain %v does not have the 'vpc_options' block defined.", [os_domain.address]),
		"resource": os_domain,
		"context": {"vpc_options": "undefined"},
	}
}

opensearch_domain_not_in_vpc[obj] {
	os_domain := util.opensearch_domain_resource_changes[_]
	count(os_domain.change.after.vpc_options) == 0

	obj := {
		"message": sprintf("AWS Opensearch domain %v does not have any subnet IDs defined in the 'vpc_options' block.", [os_domain.address]),
		"resource": os_domain,
		"context": {"vpc_options": os_domain.change.after.vpc_options},
	}
}

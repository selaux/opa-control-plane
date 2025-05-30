package global.systemtypes["terraform:2.0"].library.provider.aws.elasticsearch.es_domain_in_vpc.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Elasticsearch: Prohibit Elasticsearch Domains not created in VPC"
# description: >-
#   Require AWS/Elasticsearch domains to have subnets added in vpc_options.
# severity: "critical"
# platform: "terraform"
# resource-type: "aws-elasticsearch_domain"
# custom:
#   id: "aws.elasticsearch.es_domain_in_vpc"
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
#     - { scope: "resource", service: "elasticsearch", name: "elasticsearch_domain", identifier: "aws_elasticsearch_domain", argument: "vpc_options.subnet_ids" }
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
prohibit_elasticsearch_domains_not_in_vpc[violation] {
	elastic_search_domain_not_in_vpc[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

elastic_search_domain_not_in_vpc[obj] {
	es_domain_resources := util.elasticsearch_domain_resource_changes[_]
	count(es_domain_resources.change.after.vpc_options) == 0

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v does not have anything defined in the 'vpc_options' block.", [es_domain_resources.address]),
		"resource": es_domain_resources,
		"context": {"vpc_options.subnet_ids": "undefined"},
	}
}

elastic_search_domain_not_in_vpc[obj] {
	es_domain_resources := util.elasticsearch_domain_resource_changes[_]
	count(es_domain_resources.change.after.vpc_options[_].subnet_ids) == 0

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v does not have any subnet IDs defined in the 'vpc_options' block.", [es_domain_resources.address]),
		"resource": es_domain_resources,
		"context": {"vpc_options.subnet_ids": "undefined"},
	}
}

elastic_search_domain_not_in_vpc[obj] {
	es_domain_resources := util.elasticsearch_domain_resource_changes[_]
	not utils.is_key_defined(es_domain_resources.change.after, "vpc_options")

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v does not have the 'vpc_options' block defined.", [es_domain_resources.address]),
		"resource": es_domain_resources,
		"context": {"vpc_options": "undefined"},
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.elasticsearch.node_to_node_encryption.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Elasticsearch: Prohibit Elasticsearch Domains with disabled node to node encryption"
# description: Require AWS/Elasticsearch domains to have enabled node to node encryption.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-elasticsearch"
# custom:
#   id: "aws.elasticsearch.node_to_node_encryption"
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
#     - { scope: "resource", service: "elasticsearch", name: "elasticsearch_domain", identifier: "aws_elasticsearch_domain", argument: "node_to_node_encryption.enabled" }
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
prohibit_elasticsearch_domains_with_disabled_node_to_node_encryption[violation] {
	insecure_elasticsearch_domain[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_elasticsearch_domain[obj] {
	esd := util.elasticsearch_domain_resource_changes[_]
	not utils.is_key_defined(esd.change.after, "node_to_node_encryption")

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v does not have 'node_to_node_encryption' block available.", [esd.address]),
		"resource": esd,
		"context": {"node_to_node_encryption": "undefined"},
	}
}

insecure_elasticsearch_domain[obj] {
	esd := util.elasticsearch_domain_resource_changes[_]
	esd.change.after.node_to_node_encryption[_].enabled == false

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v is missing the 'node_to_node_encryption' configuration.", [esd.address]),
		"resource": esd,
		"context": {"node_to_node_encryption.enabled": false},
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.opensearch.encrypt_at_rest.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: OpenSearch: Prohibit OpenSearch Domains with disabled encryption at rest"
# description: Require AWS/OpenSearch domains to have enabled encryption at rest.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-opensearch"
# custom:
#   id: "aws.opensearch.encrypt_at_rest"
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
#     - { scope: "resource", service: "opensearch", "name": "opensearch_domain", identifier: "aws_opensearch_domain", argument: "encrypt_at_rest.enabled" }
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
prohibit_opensearch_domains_with_disabled_encrypt_at_rest[violation] {
	insecure_opensearch_domain[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_opensearch_domain[obj] {
	os_domain := util.opensearch_domain_resource_changes[_]
	not utils.is_key_defined(os_domain.change.after, "encrypt_at_rest")

	obj := {
		"message": sprintf("AWS OpenSearch domain %v does not have the 'encrypt_at_rest' block defined.", [os_domain.address]),
		"resource": os_domain,
		"context": {"encrypt_at_rest": "undefined"},
	}
}

insecure_opensearch_domain[obj] {
	os_domain := util.opensearch_domain_resource_changes[_]
	os_domain.change.after.encrypt_at_rest[_].enabled == false

	obj := {
		"message": sprintf("AWS OpenSearch domain %v 'encrypt_at_rest' disabled.", [os_domain.address]),
		"resource": os_domain,
		"context": {"encrypt_at_rest.enabled": false},
	}
}

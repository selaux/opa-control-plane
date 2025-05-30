package global.systemtypes["terraform:2.0"].library.provider.aws.elasticsearch.https_required.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Elasticsearch: Prohibit Elasticsearch Domains which does not use TLS 1.2 and have https enforced."
# description: Require AWS/Elasticsearch domains to have https enforced and use TLS 1.2.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-elasticsearch"
# custom:
#   id: "aws.elasticsearch.https_required"
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
#     - { scope: "resource", service: "elasticsearch", name: "elasticsearch_domain", identifier: "aws_elasticsearch_domain", argument: "domain_endpoint_options.tls_security_policy" }
#     - { scope: "resource", service: "elasticsearch", name: "elasticsearch_domain", identifier: "aws_elasticsearch_domain", argument: "domain_endpoint_options.enforce_https" }
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
prohibit_elasticsearch_domains_without_https_enforced[violation] {
	insecure_elasticsearch_domain[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_elasticsearch_domain[obj] {
	esd := util.elasticsearch_domain_resource_changes[_]
	not utils.is_key_defined(esd.change.after, "domain_endpoint_options")

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v is missing the 'domain_endpoint_options' configuration.", [esd.address]),
		"resource": esd,
		"context": {"domain_endpoint_options": "undefined"},
	}
}

insecure_elasticsearch_domain[obj] {
	esd := util.elasticsearch_domain_resource_changes[_]
	esd_domain_endpoint_options := esd.change.after.domain_endpoint_options[_]
	not utils.is_key_defined(esd_domain_endpoint_options, "tls_security_policy")

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v is missing the 'tls_security_policy' configuration.", [esd.address]),
		"resource": esd,
		"context": {"domain_endpoint_options.tls_security_policy": "undefined"},
	}
}

insecure_elasticsearch_domain[obj] {
	esd := util.elasticsearch_domain_resource_changes[_]
	esd.change.after.domain_endpoint_options[_].tls_security_policy == "Policy-Min-TLS-1-0-2019-07"

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v should use 'Policy-Min-TLS-1-2-2019-07' as TLS security policy", [esd.address]),
		"resource": esd,
		"context": {"domain_endpoint_options.tls_security_policy": "Policy-Min-TLS-1-0-2019-07"},
	}
}

insecure_elasticsearch_domain[obj] {
	esd := util.elasticsearch_domain_resource_changes[_]
	esd.change.after.domain_endpoint_options[_].enforce_https == false

	obj := {
		"message": sprintf("AWS Elasticsearch domain %v with 'enforce_https' domain endpoint setting disabled is prohibited.", [esd.address]),
		"resource": esd,
		"context": {"domain_endpoint_options.enforce_https": false},
	}
}

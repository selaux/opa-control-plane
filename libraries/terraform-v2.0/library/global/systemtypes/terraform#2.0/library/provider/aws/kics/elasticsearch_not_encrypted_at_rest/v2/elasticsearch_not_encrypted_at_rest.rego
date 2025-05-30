package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticsearch_not_encrypted_at_rest.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticsearch_not_encrypted_at_rest_inner[result] {
	domain := input.document[i].resource.aws_elasticsearch_domain[name]
	not domain.encrypt_at_rest
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'encrypt_at_rest' is undefined", "keyExpectedValue": "'encrypt_at_rest' should be set and enabled", "remediation": "encrypt_at_rest {\n\t\t enabled = true \n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(domain, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name], [])}
}

elasticsearch_not_encrypted_at_rest_inner[result] {
	domain := input.document[i].resource.aws_elasticsearch_domain[name]
	encrypt_at_rest := domain.encrypt_at_rest
	encrypt_at_rest.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'encrypt_at_rest.enabled' is false", "keyExpectedValue": "'encrypt_at_rest.enabled' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(domain, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[%s].encrypt_at_rest.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name, "encrypt_at_rest", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElasticSearch Not Encrypted At Rest"
# description: >-
#   Check if ElasticSearch encryption is disabled at Rest
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticsearch_not_encrypted_at_rest"
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
#     - argument: ""
#       identifier: aws_elasticsearch_domain
#       name: ""
#       scope: resource
#       service: ""
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
elasticsearch_not_encrypted_at_rest_snippet[violation] {
	elasticsearch_not_encrypted_at_rest_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticsearch_encryption_with_kms_is_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticsearch_encryption_with_kms_is_disabled_inner[result] {
	domain := input.document[i].resource.aws_elasticsearch_domain[name]
	rest := domain.encrypt_at_rest
	not rest.kms_key_id
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_elasticsearch_domain[%s].encrypt_at_rest.kms_key_id' is undefined", [name]), "keyExpectedValue": sprintf("'aws_elasticsearch_domain[%s].encrypt_at_rest.kms_key_id' should be set with encryption at rest", [name]), "resourceName": tf_lib.get_resource_name(domain, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[%s].encrypt_at_rest", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElasticSearch Encryption With KMS Disabled"
# description: >-
#   Check if any ElasticSearch domain isn't encrypted with KMS.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticsearch_encryption_with_kms_is_disabled"
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
elasticsearch_encryption_with_kms_is_disabled_snippet[violation] {
	elasticsearch_encryption_with_kms_is_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_without_ssl_certificate.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_without_ssl_certificate_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_stage[name]
	not resource.client_certificate_id
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'client_certificate_id' is undefined", "keyExpectedValue": "Attribute 'client_certificate_id' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_stage", "searchKey": sprintf("aws_api_gateway_stage[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Without SSL Certificate"
# description: >-
#   SSL Client Certificate should be enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_without_ssl_certificate"
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
#       identifier: aws_api_gateway_stage
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
api_gateway_without_ssl_certificate_snippet[violation] {
	api_gateway_without_ssl_certificate_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

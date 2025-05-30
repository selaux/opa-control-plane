package global.systemtypes["terraform:2.0"].library.provider.aws.kics.certificate_has_expired.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

certificate_has_expired_inner[result] {
	resource := input.document[i].resource[resourceType]
	services := {"aws_acm_certificate", "aws_api_gateway_domain_name", "aws_iam_server_certificate"}
	resourceType == services[_]
	expiration_date := resource[name].certificate_body.expiration_date
	common_lib.expired(expiration_date)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].certificate_body has expired", [resourceType, name]), "keyExpectedValue": sprintf("%s[%s].certificate_body should not have expired", [resourceType, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].certificate_body", [resourceType, name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Certificate Has Expired"
# description: >-
#   Expired SSL/TLS certificates should be removed
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.certificate_has_expired"
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
certificate_has_expired_snippet[violation] {
	certificate_has_expired_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

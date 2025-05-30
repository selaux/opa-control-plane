package global.systemtypes["terraform:2.0"].library.provider.aws.kics.certificate_rsa_key_bytes_lower_than_256.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

certificate_rsa_key_bytes_lower_than_256_inner[result] {
	resource := input.document[i].resource[resourceType]
	services := {"aws_acm_certificate", "aws_api_gateway_domain_name", "aws_iam_server_certificate"}
	resourceType == services[_]
	resource[name].certificate_body.rsa_key_bytes < 256
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].certificate_body does not use a RSA key with a length equal to or higher than 256 bytes", [resourceType, name]), "keyExpectedValue": sprintf("%s[%s].certificate_body uses a RSA key with a length equal to or higher than 256 bytes", [resourceType, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].certificate_body", [resourceType, name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Certificate RSA Key Bytes Lower Than 256"
# description: >-
#   The certificate should use a RSA key with a length equal to or higher than 256 bytes
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.certificate_rsa_key_bytes_lower_than_256"
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
certificate_rsa_key_bytes_lower_than_256_snippet[violation] {
	certificate_rsa_key_bytes_lower_than_256_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

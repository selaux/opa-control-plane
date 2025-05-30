package global.systemtypes["terraform:2.0"].library.provider.aws.kics.secure_ciphers_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

secure_ciphers_disabled_inner[result] {
	resource := input.document[i].resource.aws_cloudfront_distribution[name]
	resource.viewer_certificate.cloudfront_default_certificate == false
	not checkMinProtocolVersion(resource.viewer_certificate.minimum_protocol_version)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version doesn't start with TLSv1.1 or TLSv1.2", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version should start with TLSv1.1 or TLSv1.2", [name]), "remediation": json.marshal({"after": "TLSv1.2", "before": sprintf("%s", [resource.viewer_certificate.minimum_protocol_version])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version", [name])}
}

checkMinProtocolVersion(protocolVersion) {
	startswith(protocolVersion, "TLSv1.1")
} else {
	startswith(protocolVersion, "TLSv1.2")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Secure Ciphers Disabled"
# description: >-
#   Check if secure ciphers aren't used in CloudFront
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.secure_ciphers_disabled"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
#       identifier: aws_cloudfront_distribution
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
secure_ciphers_disabled_snippet[violation] {
	secure_ciphers_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

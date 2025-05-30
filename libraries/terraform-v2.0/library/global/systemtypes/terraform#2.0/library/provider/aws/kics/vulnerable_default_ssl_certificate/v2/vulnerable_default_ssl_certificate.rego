package global.systemtypes["terraform:2.0"].library.provider.aws.kics.vulnerable_default_ssl_certificate.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

vulnerable_default_ssl_certificate_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	not common_lib.valid_key(resource, "viewer_certificate")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_cloudfront_distribution[%s].viewer_certificate is undefined or null", [name]), "keyExpectedValue": sprintf("aws_cloudfront_distribution[%s].viewer_certificate should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("aws_cloudfront_distribution[%s]", [name])}
}

vulnerable_default_ssl_certificate_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.viewer_certificate.cloudfront_default_certificate
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'cloudfront_default_certificate' is 'true'", "keyExpectedValue": "Attribute 'cloudfront_default_certificate' should be 'false' or not defined", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("aws_cloudfront_distribution[%s].viewer_certificate", [name])}
}

vulnerable_default_ssl_certificate_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	hasCustomConfig(resource.viewer_certificate)
	attr := {"minimum_protocol_version", "ssl_support_method"}
	attributes := attr[a]
	not common_lib.valid_key(resource.viewer_certificate, attributes)
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("Attribute '%s' is not defined", [attributes]), "keyExpectedValue": "Attributes 'ssl_support_method' and 'minimum_protocol_version' should be defined when one of 'acm_certificate_arn' or 'iam_certificate_id' is declared.", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("aws_cloudfront_distribution[%s].viewer_certificate", [name])}
}

hasCustomConfig(viewer_certificate) {
	common_lib.valid_key(viewer_certificate, "acm_certificate_arn")
}

hasCustomConfig(viewer_certificate) {
	common_lib.valid_key(viewer_certificate, "iam_certificate_id")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Vulnerable Default SSL Certificate"
# description: >-
#   CloudFront web distributions should use custom (and not default) SSL certificates. Custom SSL certificates allow only defined users to access content by using an alternate domain name instead of the default one.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.vulnerable_default_ssl_certificate"
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
vulnerable_default_ssl_certificate_snippet[violation] {
	vulnerable_default_ssl_certificate_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

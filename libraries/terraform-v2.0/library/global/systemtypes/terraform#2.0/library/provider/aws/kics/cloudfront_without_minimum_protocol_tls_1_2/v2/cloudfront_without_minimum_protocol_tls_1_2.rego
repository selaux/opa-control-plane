package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudfront_without_minimum_protocol_tls_1_2.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudfront_without_minimum_protocol_tls_1_2_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true
	not common_lib.valid_key(resource, "viewer_certificate")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate' is undefined or null", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate' should be defined and not null", [name]), "remediation": "viewer_certificate {\n\t\t cloudfront_default_certificate = false \n\t\t minimum_protocol_version = \"TLSv1.2_2021\"\n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name], [])}
}

cloudfront_without_minimum_protocol_tls_1_2_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true
	resource.viewer_certificate.cloudfront_default_certificate == true
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.cloudfront_default_certificate' is 'true'", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.cloudfront_default_certificate' should be 'false'", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.cloudfront_default_certificate", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name, "viewer_certificate", "cloudfront_default_certificate"], [])}
}

cloudfront_without_minimum_protocol_tls_1_2_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true
	resource.viewer_certificate.cloudfront_default_certificate == false
	protocol_version := resource.viewer_certificate.minimum_protocol_version
	not common_lib.is_recommended_tls(protocol_version)
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' is %s", [name, protocol_version]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' should be TLSv1.2_x", [name]), "remediation": json.marshal({"after": "TLSv1.2_2021", "before": sprintf("%s", [protocol_version])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name, "viewer_certificate", "minimum_protocol_version"], [])}
}

cloudfront_without_minimum_protocol_tls_1_2_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true
	resource.viewer_certificate.cloudfront_default_certificate == false
	not common_lib.valid_key(resource.viewer_certificate, "minimum_protocol_version")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' is undefined or null", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' should be defined and not null", [name]), "remediation": "minimum_protocol_version = \"TLSv1.2_2021\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name, "viewer_certificate"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudFront Without Minimum Protocol TLS 1.2"
# description: >-
#   CloudFront Minimum Protocol version should be at least TLS 1.2
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudfront_without_minimum_protocol_tls_1_2"
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
cloudfront_without_minimum_protocol_tls_1_2_snippet[violation] {
	cloudfront_without_minimum_protocol_tls_1_2_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

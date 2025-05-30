package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cdn_configuration_is_missing.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cdn_configuration_is_missing_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	not common_lib.valid_key(resource, "enabled")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].enabled is not defined", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].enabled should be set to 'true'", [name]), "remediation": "enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name], [])}
}

cdn_configuration_is_missing_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == false
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].enabled is configured as 'false'", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].enabled should be set to 'true'", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s].enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name, "enabled"], [])}
}

cdn_configuration_is_missing_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	not common_lib.valid_key(resource, "origin")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].origin is not defined", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].origin should be defined", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CDN Configuration Is Missing"
# description: >-
#   Content Delivery Network (CDN) service is used within an AWS account to secure and accelerate the delivery of websites. The use of a CDN can provide a layer of security between your origin content and the destination.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cdn_configuration_is_missing"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
cdn_configuration_is_missing_snippet[violation] {
	cdn_configuration_is_missing_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

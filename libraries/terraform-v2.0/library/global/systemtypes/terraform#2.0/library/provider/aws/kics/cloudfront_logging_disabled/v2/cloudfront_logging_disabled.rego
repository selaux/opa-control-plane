package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudfront_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudfront_logging_disabled_inner[result] {
	resource := input.document[i].resource
	cloudfront := resource.aws_cloudfront_distribution[name]
	cloudfront.enabled == true
	not common_lib.valid_key(cloudfront, "logging_config")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_cloudfront_distribution[%s].logging_config is undefined", [name]), "keyExpectedValue": sprintf("aws_cloudfront_distribution[%s].logging_config should be defined", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("aws_cloudfront_distribution[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudFront Logging Disabled"
# description: >-
#   AWS CloudFront distributions should have logging enabled to collect all viewer requests, which means the attribute 'logging_config' should be defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudfront_logging_disabled"
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
cloudfront_logging_disabled_snippet[violation] {
	cloudfront_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudtrail_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudtrail_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_cloudtrail[name]
	resource.enable_logging == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_cloudtrail.%s.enable_logging is false", [name]), "keyExpectedValue": sprintf("aws_cloudtrail.%s.enable_logging should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail.%s.enable_logging", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudtrail", name, "enable_logging"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudTrail Logging Disabled"
# description: >-
#   Checks if logging is enabled for CloudTrail.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudtrail_logging_disabled"
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
#       identifier: aws_cloudtrail
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
cloudtrail_logging_disabled_snippet[violation] {
	cloudtrail_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

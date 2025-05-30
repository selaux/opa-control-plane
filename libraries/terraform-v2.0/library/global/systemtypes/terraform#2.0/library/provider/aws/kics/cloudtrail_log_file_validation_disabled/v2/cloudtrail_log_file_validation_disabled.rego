package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudtrail_log_file_validation_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudtrail_log_file_validation_disabled_inner[result] {
	resource := input.document[i].resource.aws_cloudtrail[name]
	resource.enable_log_file_validation == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_cloudtrail[%s].enable_log_file_validation' is false", [name]), "keyExpectedValue": sprintf("'aws_cloudtrail[%s].enable_log_file_validation' should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s].enable_log_file_validation", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudtrail", name, "enable_log_file_validation"], [])}
}

cloudtrail_log_file_validation_disabled_inner[result] {
	resource := input.document[i].resource.aws_cloudtrail[name]
	not common_lib.valid_key(resource, "enable_log_file_validation")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_cloudtrail[%s].enable_log_file_validation' is undefined", [name]), "keyExpectedValue": sprintf("'aws_cloudtrail[%s].enable_log_file_validation' should be set", [name]), "remediation": "enable_log_file_validation = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudtrail", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudTrail Log File Validation Disabled"
# description: >-
#   CloudTrail log file validation should be enabled to determine whether a log file has not been tampered
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudtrail_log_file_validation_disabled"
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
cloudtrail_log_file_validation_disabled_snippet[violation] {
	cloudtrail_log_file_validation_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

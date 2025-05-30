package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudtrail_sns_topic_name_undefined.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudtrail_sns_topic_name_undefined_inner[result] {
	cloudtrail := input.document[i].resource.aws_cloudtrail[name]
	isUndefined(cloudtrail)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_cloudtrail[%s].sns_topic_name' is undefined or null", [name]), "keyExpectedValue": sprintf("'aws_cloudtrail[%s].sns_topic_name' should be set and should not be null", [name]), "resourceName": tf_lib.get_resource_name(cloudtrail, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s]", [name])}
}

isUndefined(resource) {
	not common_lib.valid_key(resource, "sns_topic_name")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudTrail SNS Topic Name Undefined"
# description: >-
#   Check if SNS topic name is set for CloudTrail
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudtrail_sns_topic_name_undefined"
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
cloudtrail_sns_topic_name_undefined_snippet[violation] {
	cloudtrail_sns_topic_name_undefined_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

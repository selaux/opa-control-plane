package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudtrail_not_integrated_with_cloudwatch.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudtrail_not_integrated_with_cloudwatch_inner[result] {
	document := input.document[i]
	cloudtrail := document.resource.aws_cloudtrail[name]
	attr := {"cloud_watch_logs_group_arn", "cloud_watch_logs_role_arn"}
	attribute := attr[a]
	not common_lib.valid_key(cloudtrail, attribute)
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_cloudtrail[%s].%s is undefined or null", [name, attribute]), "keyExpectedValue": sprintf("aws_cloudtrail[%s].%s should be defined and not null", [name, attribute]), "resourceName": tf_lib.get_resource_name(cloudtrail, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudTrail Not Integrated With CloudWatch"
# description: >-
#   CloudTrail should be integrated with CloudWatch
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudtrail_not_integrated_with_cloudwatch"
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
cloudtrail_not_integrated_with_cloudwatch_snippet[violation] {
	cloudtrail_not_integrated_with_cloudwatch_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

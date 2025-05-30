package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudwatch_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudwatch_logging_disabled_inner[result] {
	resource := input.document[i].resource
	route := resource.aws_route53_zone[name]
	not resource.aws_route53_query_log[name]
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'aws_route53_query_log' is undefined", "keyExpectedValue": "'aws_route53_query_log' should be set for respective 'aws_route53_zone'", "resourceName": tf_lib.get_resource_name(route, name), "resourceType": "aws_route53_zone", "searchKey": sprintf("aws_route53_zone[%s]", [name])}
}

# TODO review this query...
# all resources should have different names
cloudwatch_logging_disabled_inner[result] {
	route := input.document[i].resource.aws_route53_query_log[name]
	log_group := route.cloudwatch_log_group_arn
	not regex.match(name, log_group)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'aws_route53_query_log' log group does not match with the log name", "keyExpectedValue": "'aws_route53_query_log' log group refers to the query log", "resourceName": tf_lib.get_resource_name(route, name), "resourceType": "aws_route53_query_log", "searchKey": sprintf("aws_route53_query_log[%s].cloudwatch_log_group_arn", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudWatch Logging Disabled"
# description: >-
#   Check if CloudWatch logging is disabled for Route53 hosted zones
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudwatch_logging_disabled"
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
#       identifier: aws_route53_query_log
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_route53_zone
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
cloudwatch_logging_disabled_snippet[violation] {
	cloudwatch_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

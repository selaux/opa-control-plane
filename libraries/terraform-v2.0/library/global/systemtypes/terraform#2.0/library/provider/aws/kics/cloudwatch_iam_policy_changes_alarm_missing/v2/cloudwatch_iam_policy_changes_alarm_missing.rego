package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudwatch_iam_policy_changes_alarm_missing.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib

expressionArr := [
	{
		"op": "=",
		"value": "DeleteGroupPolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteRolePolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteUserPolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "PutGroupPolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "PutRolePolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "PutUserPolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "CreatePolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeletePolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "CreatePolicyVersion",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeletePolicyVersion",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "AttachRolePolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DetachRolePolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "AttachUserPolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DetachUserPolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "AttachGroupPolicy",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DetachGroupPolicy",
		"name": "$.eventName",
	},
]

check_selector(filter, value, op, name) {
	selector := common_lib.find_selector_by_value(filter, value)
	selector._op == op
	selector._selector == name
}

# {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}
check_expression_missing(resName, filter, doc) {
	alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
	contains(alarm.metric_name, resName)

	count({x | exp := expressionArr[n]; common_lib.check_selector(filter, exp.value, exp.op, exp.name) == false; x := exp}) == 0
}

cloudwatch_iam_policy_changes_alarm_missing_inner[result] {
	doc := input.document[i]
	resources := doc.resource.aws_cloudwatch_log_metric_filter
	allPatternsCount := count([x | [path, value] := walk(resources); filter := common_lib.json_unmarshal(value.pattern); x = filter])
	count([x | [path, value] := walk(resources); filter := common_lib.json_unmarshal(value.pattern); not check_expression_missing(path[0], filter, doc); x = filter]) == allPatternsCount
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_cloudwatch_log_metric_filter not filtering pattern {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)} or not associated with any aws_cloudwatch_metric_alarm", "keyExpectedValue": "aws_cloudwatch_log_metric_filter should have pattern {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)} and be associated an aws_cloudwatch_metric_alarm", "resourceName": "unknown", "resourceType": "aws_cloudwatch_log_metric_filter", "searchKey": "resource", "searchLine": common_lib.build_search_line([], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudWatch IAM Policy Changes Alarm Missing"
# description: >-
#   Ensure a log metric filter and alarm exist for IAM policy changes
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudwatch_iam_policy_changes_alarm_missing"
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
#     []
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
cloudwatch_iam_policy_changes_alarm_missing_snippet[violation] {
	cloudwatch_iam_policy_changes_alarm_missing_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

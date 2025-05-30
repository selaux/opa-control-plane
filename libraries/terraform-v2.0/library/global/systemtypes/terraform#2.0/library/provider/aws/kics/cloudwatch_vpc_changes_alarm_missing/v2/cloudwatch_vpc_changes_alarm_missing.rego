package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudwatch_vpc_changes_alarm_missing.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib

expressionArr := [
	{
		"op": "=",
		"value": "CreateVpc",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteVpc",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "ModifyVpcAttribute",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "AcceptVpcPeeringConnection",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "CreateVpcPeeringConnection",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteVpcPeeringConnection",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "RejectVpcPeeringConnection",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "AttachClassicLinkVpc",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DetachClassicLinkVpc",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DisableVpcClassicLink",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "EnableVpcClassicLink",
		"name": "$.eventName",
	},
]

# { ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }
check_expression_missing(resName, filter, doc) {
	alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
	contains(alarm.metric_name, resName)
	filter._kics_filter_expr._op == "||"
	count({x | exp := expressionArr[n]; commonLib.check_selector(filter, exp.value, exp.op, exp.name) == false; x := exp}) == 0
}

cloudwatch_vpc_changes_alarm_missing_inner[result] {
	doc := input.document[i]
	resources := doc.resource.aws_cloudwatch_log_metric_filter
	allPatternsCount := count([x | [path, value] := walk(resources); filter := commonLib.json_unmarshal(value.pattern); x = filter])
	count([x | [path, value] := walk(resources); filter := commonLib.json_unmarshal(value.pattern); not check_expression_missing(path[0], filter, doc); x = filter]) == allPatternsCount
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_cloudwatch_log_metric_filter not filtering pattern { ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) } or not associated with any aws_cloudwatch_metric_alarm", "keyExpectedValue": "aws_cloudwatch_log_metric_filter should have pattern { ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) } and be associated an aws_cloudwatch_metric_alarm", "resourceName": "unknown", "resourceType": "aws_cloudwatch_log_metric_filter", "searchKey": "resource", "searchLine": commonLib.build_search_line([], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudWatch VPC Changes Alarm Missing"
# description: >-
#   Ensure a log metric filter and alarm exist for VPC changes
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudwatch_vpc_changes_alarm_missing"
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
cloudwatch_vpc_changes_alarm_missing_snippet[violation] {
	cloudwatch_vpc_changes_alarm_missing_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

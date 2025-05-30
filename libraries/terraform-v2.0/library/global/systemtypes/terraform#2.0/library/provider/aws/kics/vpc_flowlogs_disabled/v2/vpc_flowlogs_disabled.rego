package global.systemtypes["terraform:2.0"].library.provider.aws.kics.vpc_flowlogs_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

vpc_flowlogs_disabled_inner[result] {
	resource := input.document[i].resource
	awsVpc := resource.aws_vpc[name_vpc]
	awsVpcId := sprintf("${aws_vpc.%s.id}", [name_vpc])
	awsFlowLogsId := [vpc_id | vpc_id := resource.aws_flow_log[_].vpc_id]
	not common_lib.inArray(awsFlowLogsId, awsVpcId)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_vpc[%s] is not the same as Flow Logs VPC id", [name_vpc]), "keyExpectedValue": sprintf("aws_vpc[%s] should be the same as Flow Logs VPC id", [name_vpc]), "resourceName": name_vpc, "resourceType": "aws_vpc", "searchKey": sprintf("aws_vpc[%s]", [name_vpc]), "searchLine": common_lib.build_search_line(["resource", "aws_vpc", name_vpc], [])}
}

vpc_flowlogs_disabled_inner[result] {
	awsFlowLogsId := input.document[i].resource.aws_flow_log[name_logs]
	not common_lib.valid_key(awsFlowLogsId, "vpc_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_flow_log[%s].vpc_id is undefined or null", [name_logs]), "keyExpectedValue": sprintf("aws_flow_log[%s].vpc_id should be defined and not null", [name_logs]), "resourceName": name_logs, "resourceType": "aws_flow_log", "searchKey": sprintf("aws_flow_log[%s]", [name_logs]), "searchLine": common_lib.build_search_line(["resource", "aws_flow_log", name_logs], [])}
}

vpc_flowlogs_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_flow_log", "enable_flow_log")
	module[keyToCheck] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s.%s is set to false", [name, keyToCheck]), "keyExpectedValue": sprintf("%s.%s should be set to true", [name, keyToCheck]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("%s.%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck], [])}
}

vpc_flowlogs_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_flow_log", "enable_flow_log")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s.%s is undefined", [name, keyToCheck]), "keyExpectedValue": sprintf("%s.%s should be set to true", [name, keyToCheck]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("%s", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: VPC FlowLogs Disabled"
# description: >-
#   Every VPC resource should have an associated Flow Log
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.vpc_flowlogs_disabled"
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
#       identifier: aws_flow_log
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_vpc
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
vpc_flowlogs_disabled_snippet[violation] {
	vpc_flowlogs_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

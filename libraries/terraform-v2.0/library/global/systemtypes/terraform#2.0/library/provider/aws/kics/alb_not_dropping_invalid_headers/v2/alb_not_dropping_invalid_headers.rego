package global.systemtypes["terraform:2.0"].library.provider.aws.kics.alb_not_dropping_invalid_headers.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

alb_not_dropping_invalid_headers_inner[result] {
	resource := input.document[i].resource[name]
	types := {"aws_alb", "aws_lb"}
	name == types[x]
	res := resource[m]
	check_load_balancer_type(res, "load_balancer_type")
	res.drop_invalid_header_fields == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[{{%s}}].drop_invalid_header_fields is set to false", [types[x], m]), "keyExpectedValue": sprintf("%s[{{%s}}].drop_invalid_header_fields should be set to true", [types[x], m]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(res, m), "resourceType": types[x], "searchKey": sprintf("%s[{{%s}}].drop_invalid_header_fields", [types[x], m]), "searchLine": common_lib.build_search_line(["resource", types[x], m, "drop_invalid_header_fields"], [])}
}

alb_not_dropping_invalid_headers_inner[result] {
	resource := input.document[i].resource[name]
	types := {"aws_alb", "aws_lb"}
	name == types[x]
	res := resource[m]
	check_load_balancer_type(res, "load_balancer_type")
	not common_lib.valid_key(res, "drop_invalid_header_fields")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[{{%s}}].drop_invalid_header_fields is missing", [types[x], m]), "keyExpectedValue": sprintf("%s[{{%s}}].drop_invalid_header_fields should be set to true", [types[x], m]), "remediation": "drop_invalid_header_fields = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(res, m), "resourceType": types[x], "searchKey": sprintf("%s[{{%s}}]", [types[x], m]), "searchLine": common_lib.build_search_line(["resource", types[x], m], [])}
}

alb_not_dropping_invalid_headers_inner[result] {
	module := input.document[i].module[name]
	keyToCheckLbt := common_lib.get_module_equivalent_key("aws", module.source, "aws_lb", "load_balancer_type")
	check_load_balancer_type(module, keyToCheckLbt)
	keyToCheckDihf := common_lib.get_module_equivalent_key("aws", module.source, "aws_lb", "drop_invalid_header_fields")
	module[keyToCheckDihf] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("module[%s].drop_invalid_header_fields is set to false", [name]), "keyExpectedValue": sprintf("module[%s].drop_invalid_header_fields should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].drop_invalid_header_fields", [name]), "searchLine": common_lib.build_search_line(["module", name, keyToCheckDihf], [])}
}

alb_not_dropping_invalid_headers_inner[result] {
	module := input.document[i].module[name]
	keyToCheckLbt := common_lib.get_module_equivalent_key("aws", module.source, "aws_lb", "load_balancer_type")
	check_load_balancer_type(module, keyToCheckLbt)
	keyToCheckDihf := common_lib.get_module_equivalent_key("aws", module.source, "aws_lb", "drop_invalid_header_fields")
	not common_lib.valid_key(module, keyToCheckDihf)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("module[%s].drop_invalid_header_fields is missing", [name]), "keyExpectedValue": sprintf("module[%s].drop_invalid_header_fields should be set to true", [name]), "remediation": "drop_invalid_header_fields = true", "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

check_load_balancer_type(res, lbt) {
	res[lbt] == "application"
} else {
	not common_lib.valid_key(res, lbt)
} else = false

# METADATA: library-snippet
# version: v1
# title: "KICS: ALB Not Dropping Invalid Headers"
# description: >-
#   It's considered a best practice when using Application Load Balancers to drop invalid header fields
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.alb_not_dropping_invalid_headers"
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
#       identifier: aws_alb
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_lb
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
alb_not_dropping_invalid_headers_snippet[violation] {
	alb_not_dropping_invalid_headers_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

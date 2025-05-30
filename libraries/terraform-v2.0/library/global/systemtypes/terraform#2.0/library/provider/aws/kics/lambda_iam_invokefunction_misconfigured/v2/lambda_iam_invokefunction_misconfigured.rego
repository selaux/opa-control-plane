package global.systemtypes["terraform:2.0"].library.provider.aws.kics.lambda_iam_invokefunction_misconfigured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

#CxPolicy for ressource iam policy
lambda_iam_invokefunction_misconfigured_inner[result] {
	resourceType := {"aws_iam_group_policy", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}
	resource := input.document[i].resource[resourceType[idx]][name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	check_iam_action(statement) == true
	not check_iam_ressource(statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].policy allows access to function (unqualified ARN) and its sub-resources, add another statement with \":*\" to function name", [name]), "keyExpectedValue": sprintf("%s[%s].policy should be misconfigured", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType[idx], "searchKey": sprintf("%s[%s].policy", [resourceType[idx], name])}
}

check_iam_ressource(statement) {
	is_string(statement.Resource)
	regex.match("(^arn:aws:lambda:.*:.*:function:[a-zA-Z0-9_-]+:[*]$)", statement.Resource)
	regex.match("(^arn:aws:lambda:.*:.*:function:[a-zA-Z0-9_-]+$)", statement.Resource)
} else {
	is_array(statement.Resource)
	regex.match("(^arn:aws:lambda:.*:.*:function:[a-zA-Z0-9_-]+:[*]$)", statement.Resource[_])
	regex.match("(^arn:aws:lambda:.*:.*:function:[a-zA-Z0-9_-]+$)", statement.Resource[_])
}

check_iam_action(statement) {
	any([regex.match("(^lambda:InvokeFunction$|^lambda:[*]$)", statement.actions[_]), statement.actions[_] == "*"])
} else {
	any([regex.match("(^lambda:InvokeFunction$|^lambda:[*]$)", statement.Actions[_]), statement.Actions[_] == "*"])
} else {
	is_array(statement.Action)
	any([regex.match("(^lambda:InvokeFunction$|^lambda:[*]$)", statement.Action[_]), statement.Action[_] == "*"])
} else {
	is_string(statement.Action)
	any([regex.match("(^lambda:InvokeFunction$|^lambda:[*]$)", statement.Action), statement.Action == "*"])
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Lambda IAM InvokeFunction Misconfigured"
# description: >-
#   Lambda permission may be misconfigured if the action field is not filled in by 'lambda:InvokeFunction'
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.lambda_iam_invokefunction_misconfigured"
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
#       identifier: aws_iam_policy
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
lambda_iam_invokefunction_misconfigured_snippet[violation] {
	lambda_iam_invokefunction_misconfigured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

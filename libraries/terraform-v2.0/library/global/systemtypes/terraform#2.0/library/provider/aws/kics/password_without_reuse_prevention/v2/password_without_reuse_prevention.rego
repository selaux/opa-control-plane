package global.systemtypes["terraform:2.0"].library.provider.aws.kics.password_without_reuse_prevention.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

password_without_reuse_prevention_inner[result] {
	password_policy := input.document[i].resource.aws_iam_account_password_policy[name]
	not common_lib.valid_key(password_policy, "password_reuse_prevention")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'password_reuse_prevention' is undefined", "keyExpectedValue": "'password_reuse_prevention' should be set with value 24", "remediation": "password_reuse_prevention = 24", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(password_policy, name), "resourceType": "aws_iam_account_password_policy", "searchKey": sprintf("aws_iam_account_password_policy[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name], [])}
}

password_without_reuse_prevention_inner[result] {
	password_policy := input.document[i].resource.aws_iam_account_password_policy[name]
	rp := password_policy.password_reuse_prevention
	rp < 24
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'password_reuse_prevention' is lower than 24", "keyExpectedValue": "'password_reuse_prevention' should be 24", "remediation": json.marshal({"after": "24", "before": sprintf("%d", [rp])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(password_policy, name), "resourceType": "aws_iam_account_password_policy", "searchKey": sprintf("aws_iam_account_password_policy[%s].password_reuse_prevention", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name, "password_reuse_prevention"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Password Without Reuse Prevention"
# description: >-
#   Check if IAM account password has the reuse password configured with 24
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.password_without_reuse_prevention"
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
#       identifier: aws_iam_account_password_policy
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
password_without_reuse_prevention_snippet[violation] {
	password_without_reuse_prevention_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_user_too_many_access_keys.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_user_too_many_access_keys_inner[result] {
	resource := input.document[i].resource.aws_iam_access_key[name]
	user := split(resource.user, ".")[1]
	count({x | r := input.document[_].resource.aws_iam_access_key[x]; split(r.user, ".")[1] == user}) > 1
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "More than one Access Key associated with the same IAM User", "keyExpectedValue": "One Access Key associated with the same IAM User", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_access_key", "searchKey": sprintf("aws_iam_access_key[%s].user", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM User Has Too Many Access Keys"
# description: >-
#   Any IAM User should not have more than one access key since it increases the risk of unauthorized access and compromise credentials
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_user_too_many_access_keys"
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
iam_user_too_many_access_keys_snippet[violation] {
	iam_user_too_many_access_keys_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_policies_attached_to_user.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

resourcesTest = ["aws_iam_policy_attachment", "aws_iam_user_policy", "aws_iam_user_policy_attachment"]

iam_policies_attached_to_user_inner[result] {
	resource := input.document[i].resource[resourcesTest[idx]][name]
	resource.user
	result := {"documentId": input.document[i].id, "issueType": "RedundantAttribute", "keyActualValue": "'user' exists", "keyExpectedValue": "'user' is redundant", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourcesTest[idx], "searchKey": sprintf("%s[{{%s}}].user", [resourcesTest[idx], name])}
}

iam_policies_attached_to_user_inner[result] {
	resource := input.document[i].resource[resourcesTest[idx]][name]
	resource.users != null
	is_array(resource.users)
	count(resource.users) > 0
	result := {"documentId": input.document[i].id, "issueType": "RedundantAttribute", "keyActualValue": "'users' exists", "keyExpectedValue": "'users' is redundant", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourcesTest[idx], "searchKey": sprintf("%s[{{%s}}].users", [resourcesTest[idx], name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Policies Attached To User"
# description: >-
#   IAM policies should be attached only to groups or roles
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_policies_attached_to_user"
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
#       identifier: aws_iam_policy_attachment
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_iam_user_policy
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_iam_user_policy_attachment
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
iam_policies_attached_to_user_snippet[violation] {
	iam_policies_attached_to_user_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

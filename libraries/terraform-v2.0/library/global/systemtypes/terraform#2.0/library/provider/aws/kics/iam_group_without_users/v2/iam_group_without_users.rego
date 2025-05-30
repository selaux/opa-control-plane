package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_group_without_users.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_group_without_users_inner[result] {
	iam_group := input.document[i].resource.aws_iam_group[name]
	without_users(name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_iam_group[%s] is not associated with an aws_iam_group_membership that has at least one user set", [name]), "keyExpectedValue": sprintf("aws_iam_group[%s] should be associated with an aws_iam_group_membership that has at least one user set", [name]), "resourceName": tf_lib.get_resource_name(iam_group, name), "resourceType": "aws_iam_group", "searchKey": sprintf("aws_iam_group[%s]", [name])}
}

without_users(name) {
	count({x | resource := input.document[x].resource.aws_iam_group_membership; has_membership_associated(resource, name); not empty(resource)}) == 0
}

has_membership_associated(resource, name) {
	attributeSplit := split(resource[_].group, ".")
	attributeSplit[1] == name
}

empty(resource) {
	count(resource[_].users) == 0
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Group Without Users"
# description: >-
#   IAM Group should have at least one user associated
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_group_without_users"
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
#       identifier: aws_iam_group
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
iam_group_without_users_snippet[violation] {
	iam_group_without_users_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

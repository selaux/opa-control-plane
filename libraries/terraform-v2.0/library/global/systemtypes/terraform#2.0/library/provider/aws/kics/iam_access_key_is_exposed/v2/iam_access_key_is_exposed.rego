package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_access_key_is_exposed.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_access_key_is_exposed_inner[result] {
	access_key := input.document[i].resource.aws_iam_access_key[name]
	lower(object.get(access_key, "status", "Active")) == "active"
	access_key.user == "root"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_iam_access_key[%s].user' is 'root' for an active access key", [name]), "keyExpectedValue": sprintf("'aws_iam_access_key[%s].user' should not be 'root' for an active access key", [name]), "resourceName": tf_lib.get_resource_name(access_key, name), "resourceType": "aws_iam_access_key", "searchKey": sprintf("aws_iam_access_key[%s].user", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Access Key Is Exposed"
# description: >-
#   IAM Access Key should not be active for root users
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_access_key_is_exposed"
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
#       identifier: aws_iam_access_key
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
iam_access_key_is_exposed_snippet[violation] {
	iam_access_key_is_exposed_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

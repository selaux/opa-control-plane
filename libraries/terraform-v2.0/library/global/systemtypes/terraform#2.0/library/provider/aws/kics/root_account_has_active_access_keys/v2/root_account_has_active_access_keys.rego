package global.systemtypes["terraform:2.0"].library.provider.aws.kics.root_account_has_active_access_keys.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

root_account_has_active_access_keys_inner[result] {
	resource := input.document[i].resource.aws_iam_access_key[name]
	contains(lower(resource.user), "root")
	not common_lib.valid_key(resource, "status")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_iam_access_key[%s].status' is undefined, that defaults to 'Active'", [name]), "keyExpectedValue": sprintf("'aws_iam_access_key[%s].status' should be defined and set to 'Inactive'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_access_key", "searchKey": sprintf("aws_iam_access_key[%s]", [name])}
}

root_account_has_active_access_keys_inner[result] {
	resource := input.document[i].resource.aws_iam_access_key[name]
	contains(lower(resource.user), "root")
	resource.status == "Active"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_iam_access_key[%s].status' is set to 'Active'", [name]), "keyExpectedValue": sprintf("'aws_iam_access_key[%s].status' should be defined and set to 'Inactive'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_access_key", "searchKey": sprintf("aws_iam_access_key[%s].status", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Root Account Has Active Access Keys"
# description: >-
#   The AWS Root Account must not have active access keys associated, which means if there are access keys associated to the Root Account, they must be inactive.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.root_account_has_active_access_keys"
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
root_account_has_active_access_keys_snippet[violation] {
	root_account_has_active_access_keys_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

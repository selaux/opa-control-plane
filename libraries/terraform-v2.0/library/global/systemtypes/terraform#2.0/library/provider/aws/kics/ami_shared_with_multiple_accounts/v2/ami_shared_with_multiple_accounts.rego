package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ami_shared_with_multiple_accounts.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ami_shared_with_multiple_accounts_inner[result] {
	launch_permissions := input.document[i].resource.aws_ami_launch_permission
	account_id := launch_permissions[name].account_id
	image_id := launch_permissions[name].image_id
	count([account | launch_permissions[j].image_id == image_id; account := launch_permissions[j].account_id]) > 1
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_ami_launch_permission[%s].image_id' is shared with multiple accounts", [name]), "keyExpectedValue": sprintf("'aws_ami_launch_permission[%s].image_id' should not be shared with multiple accounts", [name]), "resourceName": tf_lib.get_resource_name(launch_permissions[name], name), "resourceType": "aws_ami_launch_permission", "searchKey": sprintf("aws_ami_launch_permission[%s].image_id", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: AMI Shared With Multiple Accounts"
# description: >-
#   Limits access to AWS AMIs by checking if more than one account is using the same image
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ami_shared_with_multiple_accounts"
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
ami_shared_with_multiple_accounts_snippet[violation] {
	ami_shared_with_multiple_accounts_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

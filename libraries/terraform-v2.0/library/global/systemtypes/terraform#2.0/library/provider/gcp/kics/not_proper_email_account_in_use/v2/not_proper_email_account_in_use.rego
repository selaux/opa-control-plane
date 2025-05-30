package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.not_proper_email_account_in_use.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

not_proper_email_account_in_use_inner[result] {
	members := input.document[i].resource.google_project_iam_binding[name].members
	mail := members[_]
	contains(mail, "gmail.com")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'members' has email address: %s", [mail]), "keyExpectedValue": "'members' cannot contain Gmail account addresses", "resourceName": tf_lib.get_resource_name(members, name), "resourceType": "google_project_iam_binding", "searchKey": sprintf("google_project_iam_binding[%s].members.%s", [name, mail])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Not Proper Email Account In Use"
# description: >-
#   Gmail accounts are being used instead of corporate credentials
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.not_proper_email_account_in_use"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: google_project_iam_binding
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
not_proper_email_account_in_use_snippet[violation] {
	not_proper_email_account_in_use_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.kms_admin_and_crypto_key_roles_in_use.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

kms_admin_and_crypto_key_roles_in_use_inner[result] {
	resource := input.document[i].resource.google_project_iam_policy[name]
	policyName := split(resource.policy_data, ".")[2]
	policy := input.document[_].data.google_iam_policy[policyName]
	count({x | binding = policy.binding[x]; binding.role == "roles/cloudkms.admin"; has_cryptokey_roles_in_use(policy, binding.members)}) != 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_iam_policy[%s].policy_data assigns a KMS admin role and CryptoKey role to the same member", [name]), "keyExpectedValue": sprintf("google_iam_policy[%s].policy_data should not assign a KMS admin role and CryptoKey role to the same member", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_project_iam_policy", "searchKey": sprintf("google_project_iam_policy[%s].policy_data", [name]), "searchLine": common_lib.build_search_line(["resource", "google_project_iam_policy", name, "policy_data"], [])}
}

has_cryptokey_roles_in_use(policy, targetMembers) {
	roles := {"roles/cloudkms.cryptoKeyDecrypter", "roles/cloudkms.cryptoKeyEncrypter", "roles/cloudkms.cryptoKeyEncrypterDecrypter"}
	binding := policy.binding[_]
	binding.role == roles[_]
	binding.members[_] == targetMembers[_]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: KMS Admin and CryptoKey Roles In Use"
# description: >-
#   Google Project IAM Policy should not assign a KMS admin role and CryptoKey role to the same member
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.kms_admin_and_crypto_key_roles_in_use"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: google_project_iam_policy
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
kms_admin_and_crypto_key_roles_in_use_snippet[violation] {
	kms_admin_and_crypto_key_roles_in_use_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

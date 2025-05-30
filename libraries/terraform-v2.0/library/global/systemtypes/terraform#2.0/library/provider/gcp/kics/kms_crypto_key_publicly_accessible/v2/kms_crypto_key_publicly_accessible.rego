package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.kms_crypto_key_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

kms_crypto_key_publicly_accessible_inner[result] {
	kmsPolicy := input.document[i].resource.google_kms_crypto_key_iam_policy[name]
	policyName := split(kmsPolicy.policy_data, ".")[2]
	publicly_accessible(policyName)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "KMS crypto key is publicly accessible", "keyExpectedValue": "KMS crypto key should not be publicly accessible", "resourceName": tf_lib.get_resource_name(kmsPolicy, name), "resourceType": "google_kms_crypto_key_iam_policy", "searchKey": sprintf("google_kms_crypto_key_iam_policy[%s].policy_data", [name]), "searchLine": common_lib.build_search_line(["resource", "google_kms_crypto_key_iam_policy", name, "policy_data"], [])}
}

publicly_accessible(policyName) {
	policy := input.document[_].data.google_iam_policy[policyName]

	options := {"allUsers", "allAuthenticatedUsers"}
	check_member(policy.binding, options[_])
}

check_member(attribute, search) {
	attribute.members[_] == search
} else {
	attribute.member == search
}

# METADATA: library-snippet
# version: v1
# title: "KICS: KMS Crypto Key is Publicly Accessible"
# description: >-
#   KMS Crypto Key should not be publicly accessible. In other words, the KMS Crypto Key policy should not set 'allUsers' or 'allAuthenticatedUsers' in the attribute 'member'/'members'
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.kms_crypto_key_publicly_accessible"
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
#       identifier: google_kms_crypto_key_iam_policy
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
kms_crypto_key_publicly_accessible_snippet[violation] {
	kms_crypto_key_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

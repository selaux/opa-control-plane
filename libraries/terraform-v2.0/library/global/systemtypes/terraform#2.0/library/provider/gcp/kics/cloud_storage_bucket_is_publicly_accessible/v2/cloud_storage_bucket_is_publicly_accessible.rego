package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.cloud_storage_bucket_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

cloud_storage_bucket_is_publicly_accessible_inner[result] {
	iam_member := input.document[i].resource.google_storage_bucket_iam_member[name]
	public_access_users := ["allUsers", "allAuthenticatedUsers"]
	not iam_member.members
	some j
	public_access_users[j] == iam_member.member
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'member' equal to '%s'", [iam_member.member]), "keyExpectedValue": "'member' not equal to 'allUsers' nor 'allAuthenticatedUsers'", "resourceName": tf_lib.get_resource_name(iam_member, name), "resourceType": "google_storage_bucket_iam_member", "searchKey": sprintf("google_storage_bucket_iam_member[%s].member", [name])}
}

cloud_storage_bucket_is_publicly_accessible_inner[result] {
	iam_member := input.document[i].resource.google_storage_bucket_iam_member[name]
	public_access_users := ["allUsers", "allAuthenticatedUsers"]
	some j, k
	public_access_users[j] == iam_member.members[k]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of the 'members' equal to 'allUsers' or 'allAuthenticatedUsers'", "keyExpectedValue": "None of the 'members' equal to 'allUsers' nor 'allAuthenticatedUsers'", "resourceName": tf_lib.get_resource_name(iam_member, name), "resourceType": "google_storage_bucket_iam_member", "searchKey": sprintf("google_storage_bucket_iam_member[%s].members", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cloud Storage Bucket Is Publicly Accessible"
# description: >-
#   Cloud Storage Bucket is anonymously or publicly accessible
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.cloud_storage_bucket_is_publicly_accessible"
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
#       identifier: google_storage_bucket_iam_member
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
cloud_storage_bucket_is_publicly_accessible_snippet[violation] {
	cloud_storage_bucket_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

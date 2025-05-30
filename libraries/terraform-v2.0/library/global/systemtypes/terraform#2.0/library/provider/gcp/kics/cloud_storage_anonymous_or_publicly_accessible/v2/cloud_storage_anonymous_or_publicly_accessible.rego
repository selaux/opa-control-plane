package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.cloud_storage_anonymous_or_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

cloud_storage_anonymous_or_publicly_accessible_inner[result] {
	resource := input.document[i].resource.google_storage_bucket_iam_binding[name]
	count(resource.members) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_storage_bucket_iam_binding[%s].members' is null", [name]), "keyExpectedValue": sprintf("'google_storage_bucket_iam_binding[%s].members' should not be null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_storage_bucket_iam_binding", "searchKey": sprintf("google_storage_bucket_iam_binding[%s].members", [name])}
}

cloud_storage_anonymous_or_publicly_accessible_inner[result] {
	resource := input.document[i].resource.google_storage_bucket_iam_binding[name]
	member := resource.members[_0]
	contains(member, "allUsers")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_storage_bucket_iam_binding[%s].members' has 'allUsers'", [name]), "keyExpectedValue": sprintf("'google_storage_bucket_iam_binding[%s].members' should not have 'allUsers'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_storage_bucket_iam_binding", "searchKey": sprintf("google_storage_bucket_iam_binding[%s].members", [name])}
}

cloud_storage_anonymous_or_publicly_accessible_inner[result] {
	resource := input.document[i].resource.google_storage_bucket_iam_binding[name]
	member := resource.members[_0]
	contains(member, "allAuthenticatedUsers")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_storage_bucket_iam_binding[%s].members' has 'allAuthenticatedUsers'", [name]), "keyExpectedValue": sprintf("'google_storage_bucket_iam_binding[%s].members' should not have 'allAuthenticatedUsers'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_storage_bucket_iam_binding", "searchKey": sprintf("google_storage_bucket_iam_binding[%s].members", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cloud Storage Anonymous or Publicly Accessible"
# description: >-
#   Cloud Storage Buckets must not be anonymously or publicly accessible, which means the attribute 'members' must not possess 'allUsers' or 'allAuthenticatedUsers'
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.cloud_storage_anonymous_or_publicly_accessible"
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
#       identifier: google_storage_bucket_iam_binding
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
cloud_storage_anonymous_or_publicly_accessible_snippet[violation] {
	cloud_storage_anonymous_or_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.bigquery_dataset_is_public.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

bigquery_dataset_is_public_inner[result] {
	resource := input.document[i].resource.google_bigquery_dataset[name]
	publiclyAccessible(resource.access)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'access.special_group' is equal to 'allAuthenticatedUsers'", "keyExpectedValue": "'access.special_group' should not equal to 'allAuthenticatedUsers'", "resourceName": tf_lib.get_specific_resource_name(resource, "google_bigquery_dataset", name), "resourceType": "google_bigquery_dataset", "searchKey": sprintf("google_bigquery_dataset[%s].access.special_group", [name])}
}

publiclyAccessible(access) {
	is_object(access)
	access.special_group == "allAuthenticatedUsers"
}

publiclyAccessible(access) {
	is_array(access)
	some i
	access[i].special_group == "allAuthenticatedUsers"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: BigQuery Dataset Is Public"
# description: >-
#   BigQuery dataset is anonymously or publicly accessible
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.bigquery_dataset_is_public"
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
#       identifier: google_bigquery_dataset
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
bigquery_dataset_is_public_snippet[violation] {
	bigquery_dataset_is_public_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

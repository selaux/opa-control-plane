package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.using_default_service_account.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

using_default_service_account_inner[result] {
	resource := input.document[i].resource.google_compute_instance[name]
	not common_lib.valid_key(resource, "service_account")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'google_compute_instance[%s].service_account' is undefined or null", [name]), "keyExpectedValue": sprintf("'google_compute_instance[%s].service_account' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s]", [name])}
}

using_default_service_account_inner[result] {
	resource := input.document[i].resource.google_compute_instance[name]
	not common_lib.valid_key(resource.service_account, "email")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'google_compute_instance[%s].service_account.email' is undefined or null", [name]), "keyExpectedValue": sprintf("'google_compute_instance[%s].service_account.email' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].service_account", [name])}
}

using_default_service_account_inner[result] {
	resource := input.document[i].resource.google_compute_instance[name]
	count(resource.service_account.email) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_instance[%s].service_account.email' is empty", [name]), "keyExpectedValue": sprintf("'google_compute_instance[%s].service_account.email' should not be empty", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].service_account.email", [name])}
}

using_default_service_account_inner[result] {
	resource := input.document[i].resource.google_compute_instance[name]
	count(resource.service_account.email) > 0
	not contains(resource.service_account.email, "@")
	not emailInVar(resource.service_account.email)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_instance[%s].service_account.email' is an email", [name]), "keyExpectedValue": sprintf("'google_compute_instance[%s].service_account.email' should not be an email", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].service_account.email", [name])}
}

using_default_service_account_inner[result] {
	resource := input.document[i].resource.google_compute_instance[name]
	contains(resource.service_account.email, "@developer.gserviceaccount.com")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_instance[%s].service_account.email' is a default Google Compute Engine service account", [name]), "keyExpectedValue": sprintf("'google_compute_instance[%s].service_account.email' should not be a default Google Compute Engine service account", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].service_account.email", [name])}
}

emailInVar(email) {
	startswith(email, "${google_service_account.")
	endswith(email, ".email}")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Using Default Service Account"
# description: >-
#   Instances should not be configured to use the Default Service Account, that has full access to all Cloud APIs, which means the attribute 'service_account' and its sub attribute 'email' must be defined. Additionally, 'email' must not be empty and must also not be a default Google Compute Engine service account.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.using_default_service_account"
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
#       identifier: google_compute_instance
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
using_default_service_account_snippet[violation] {
	using_default_service_account_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

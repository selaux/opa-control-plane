package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.disk_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

disk_encryption_disabled_inner[result] {
	resource := input.document[i].resource.google_compute_disk[name]
	not common_lib.valid_key(resource, "disk_encryption_key")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'google_compute_disk[%s].disk_encryption_key' is undefined or null", [name]), "keyExpectedValue": sprintf("'google_compute_disk[%s].disk_encryption_key' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_disk", "searchKey": sprintf("google_compute_disk[%s]", [name])}
}

disk_encryption_disabled_inner[result] {
	resource := input.document[i].resource.google_compute_disk[name]
	not common_lib.valid_key(resource.disk_encryption_key, "raw_key")
	not common_lib.valid_key(resource.disk_encryption_key, "kms_key_self_link")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'google_compute_disk[%s].disk_encryption_key.raw_key' and 'google_compute_disk[%s].disk_encryption_key.kms_key_self_link' are undefined or null", [name]), "keyExpectedValue": sprintf("'google_compute_disk[%s].disk_encryption_key.raw_key' or 'google_compute_disk[%s].disk_encryption_key.kms_key_self_link' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_disk", "searchKey": sprintf("google_compute_disk[%s].disk_encryption_key", [name])}
}

disk_encryption_disabled_inner[result] {
	resource := input.document[i].resource.google_compute_disk[name]
	key := tf_lib.check_key_empty(resource.disk_encryption_key)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_disk[%s].disk_encryption_key.%s' is not empty or null", [name, key]), "keyExpectedValue": sprintf("'google_compute_disk[%s].disk_encryption_key.%s' should not be empty or null", [name, key]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_disk", "searchKey": sprintf("google_compute_disk[%s].disk_encryption_key.%s", [name, key])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Disk Encryption Disabled"
# description: >-
#   VM disks for critical VMs must be encrypted with Customer Supplied Encryption Keys (CSEK) or with Customer-managed encryption keys (CMEK), which means the attribute 'disk_encryption_key' must be defined and its sub attributes 'raw_key' or 'kms_key_self_link' must also be defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.disk_encryption_disabled"
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
#       identifier: google_compute_disk
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
disk_encryption_disabled_snippet[violation] {
	disk_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

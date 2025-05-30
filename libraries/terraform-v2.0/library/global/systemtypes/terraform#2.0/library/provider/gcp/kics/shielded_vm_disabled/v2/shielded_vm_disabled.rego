package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.shielded_vm_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

shielded_vm_disabled_inner[result] {
	document := input.document[i]
	compute_instance := document.data.google_compute_instance[appserver]
	not common_lib.valid_key(compute_instance, "shielded_instance_config")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'shielded_instance_config' is undefined or null", "keyExpectedValue": "Attribute 'shielded_instance_config' should be defined and not null", "resourceName": tf_lib.get_resource_name(compute_instance, appserver), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s]", [appserver])}
}

shielded_vm_disabled_inner[result] {
	document := input.document[i]
	compute_instance := document.data.google_compute_instance[appserver]
	fields := ["enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring"]
	fieldTypes := fields[_]
	not common_lib.valid_key(compute_instance.shielded_instance_config, fieldTypes)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("Attribute 'shielded_instance_config.%s' is undefined", [fieldTypes]), "keyExpectedValue": sprintf("Attribute 'shielded_instance_config.%s' should be defined", [fieldTypes]), "resourceName": tf_lib.get_resource_name(compute_instance, appserver), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].shielded_instance_config", [appserver])}
}

shielded_vm_disabled_inner[result] {
	document := input.document[i]
	compute_instance := document.data.google_compute_instance[appserver]
	fields := ["enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring"]
	compute_instance.shielded_instance_config[fields[j]] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Attribute 'shielded_instance_config.%s' is false", [fields[j]]), "keyExpectedValue": sprintf("Attribute 'shielded_instance_config.%s' should be true", [fields[j]]), "resourceName": tf_lib.get_resource_name(compute_instance, appserver), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].shielded_instance_config.%s", [appserver, fields[j]])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Shielded VM Disabled"
# description: >-
#   Compute instances must be launched with Shielded VM enabled, which means the attribute 'shielded_instance_config' must be defined and its sub attributes 'enable_secure_boot', 'enable_vtpm' and 'enable_integrity_monitoring' must be set to true
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.shielded_vm_disabled"
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
shielded_vm_disabled_snippet[violation] {
	shielded_vm_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

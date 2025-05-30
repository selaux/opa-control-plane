package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.vm_serial_ports_are_enabled_for_vm_instances.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

vm_serial_ports_are_enabled_for_vm_instances_inner[result] {
	compute := input.document[i].resource.google_compute_instance[name]
	metadata := compute.metadata
	serialPortEnabled(metadata)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_compute_instance[%s].metadata.serial-port-enable is true", [name]), "keyExpectedValue": sprintf("google_compute_instance[%s].metadata.serial-port-enable should be set to false or undefined", [name]), "resourceName": tf_lib.get_resource_name(compute, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].metadata.serial-port-enable", [name])}
}

vm_serial_ports_are_enabled_for_vm_instances_inner[result] {
	project := input.document[i].resource.google_compute_project_metadata[name]
	metadata := project.metadata
	serialPortEnabled(metadata)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_compute_project_metadata[%s].metadata.serial-port-enable is true", [name]), "keyExpectedValue": sprintf("google_compute_project_metadata[%s].metadata.serial-port-enable should be set to false or undefined", [name]), "resourceName": tf_lib.get_resource_name(project, name), "resourceType": "google_compute_project_metadata", "searchKey": sprintf("google_compute_project_metadata[%s].metadata.serial-port-enable", [name])}
}

vm_serial_ports_are_enabled_for_vm_instances_inner[result] {
	metadata := input.document[i].resource.google_compute_project_metadata_item[name]
	metadata.key == "serial-port-enable"
	isTrue(metadata.value)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_compute_project_metadata[%s].value is true", [name]), "keyExpectedValue": sprintf("google_compute_project_metadata[%s].value should be set to false", [name]), "resourceName": tf_lib.get_resource_name(metadata, name), "resourceType": "google_compute_project_metadata_item", "searchKey": sprintf("google_compute_project_metadata_item[%s].value", [name])}
}

serialPortEnabled(metadata) {
	serial_enabled := object.get(metadata, "serial-port-enable", "undefined")
	isTrue(serial_enabled)
}

isTrue(value) {
	is_string(value)
	lower(value) == "true"
}

isTrue(value) {
	is_boolean(value)
	value
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Serial Ports Are Enabled For VM Instances"
# description: >-
#   Google Compute Engine VM instances should not enable serial ports. When enabled, anyone can access your VM, if they know the username, project ID, SSH key, instance name and zone
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.vm_serial_ports_are_enabled_for_vm_instances"
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
#     - argument: ""
#       identifier: google_compute_project_metadata
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: google_compute_project_metadata_item
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
vm_serial_ports_are_enabled_for_vm_instances_snippet[violation] {
	vm_serial_ports_are_enabled_for_vm_instances_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.project_wide_ssh_keys_are_enabled_in_vm_instances.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

project_wide_ssh_keys_are_enabled_in_vm_instances_inner[result] {
	compute := input.document[i].resource.google_compute_instance[name]
	metadata := compute.metadata
	ssh_keys_enabled := metadata["block-project-ssh-keys"]
	not isTrue(ssh_keys_enabled)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_compute_instance[%s].metadata.block-project-ssh-keys is %s", [name, ssh_keys_enabled]), "keyExpectedValue": sprintf("google_compute_instance[%s].metadata.block-project-ssh-keys should be true", [name]), "resourceName": tf_lib.get_resource_name(compute, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].metadata.block-project-ssh-keys", [name])}
}

project_wide_ssh_keys_are_enabled_in_vm_instances_inner[result] {
	compute := input.document[i].resource.google_compute_instance[name]
	not common_lib.valid_key(compute, "metadata")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("google_compute_instance[%s].metadata is undefined", [name]), "keyExpectedValue": sprintf("google_compute_instance[%s].metadata should be set", [name]), "resourceName": tf_lib.get_resource_name(compute, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s]", [name])}
}

project_wide_ssh_keys_are_enabled_in_vm_instances_inner[result] {
	compute := input.document[i].resource.google_compute_instance[name]
	not common_lib.valid_key(compute.metadata, "block-project-ssh-keys")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("google_compute_instance[%s].metadata.block-project-ssh-keys is undefined", [name]), "keyExpectedValue": sprintf("google_compute_instance[%s].metadata.block-project-ssh-keys should be set", [name]), "resourceName": tf_lib.get_resource_name(compute, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].metadata", [name])}
}

isTrue(ssh_keys_enabled) {
	is_string(ssh_keys_enabled)
	lower(ssh_keys_enabled) == "true"
}

isTrue(ssh_keys_enabled) {
	is_boolean(ssh_keys_enabled)
	ssh_keys_enabled
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Project-wide SSH Keys Are Enabled In VM Instances"
# description: >-
#   VM Instance should block project-wide SSH keys
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.project_wide_ssh_keys_are_enabled_in_vm_instances"
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
project_wide_ssh_keys_are_enabled_in_vm_instances_snippet[violation] {
	project_wide_ssh_keys_are_enabled_in_vm_instances_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

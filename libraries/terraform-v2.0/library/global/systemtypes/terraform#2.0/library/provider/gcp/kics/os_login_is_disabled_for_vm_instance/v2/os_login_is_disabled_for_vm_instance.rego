package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.os_login_is_disabled_for_vm_instance.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

os_login_is_disabled_for_vm_instance_inner[result] {
	compute := input.document[i].resource.google_compute_instance[name]
	metadata := compute.metadata
	oslogin := object.get(metadata, "enable-oslogin", "undefined")
	isFalse(oslogin)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_compute_instance[%s].metadata.enable-oslogin is false", [name]), "keyExpectedValue": sprintf("google_compute_instance[%s].metadata.enable-oslogin should be true or undefined", [name]), "remediation": json.marshal({"after": "true", "before": sprintf("%s", [oslogin])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(compute, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].metadata.enable-oslogin", [name]), "searchLine": common_lib.build_search_line(["resource", "google_compute_instance", name], ["metadata", "enable-oslogin"])}
}

isFalse(value) {
	is_string(value)
	lower(value) == "false"
}

isFalse(value) {
	is_boolean(value)
	not value
}

# METADATA: library-snippet
# version: v1
# title: "KICS: OSLogin Is Disabled For VM Instance"
# description: >-
#   Check if any VM instance disables OSLogin
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.os_login_is_disabled_for_vm_instance"
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
os_login_is_disabled_for_vm_instance_snippet[violation] {
	os_login_is_disabled_for_vm_instance_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

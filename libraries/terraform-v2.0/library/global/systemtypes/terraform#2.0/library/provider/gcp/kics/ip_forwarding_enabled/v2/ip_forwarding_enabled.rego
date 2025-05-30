package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.ip_forwarding_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

ip_forwarding_enabled_inner[result] {
	dt := input.document[i].resource.google_compute_instance[appserver]
	dt.can_ip_forward == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'can_ip_forward' is true", "keyExpectedValue": "Attribute 'can_ip_forward' should be set to false or Attribute 'can_ip_forward' should be undefined", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(dt, appserver), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].can_ip_forward", [appserver]), "searchLine": common_lib.build_search_line(["resource", "google_compute_instance", appserver], ["can_ip_forward"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IP Forwarding Enabled"
# description: >-
#   Instances must not have IP forwarding enabled, which means the attribute 'can_ip_forward' must not be true
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.ip_forwarding_enabled"
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
ip_forwarding_enabled_snippet[violation] {
	ip_forwarding_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.rdp_access_is_not_restricted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

rdp_access_is_not_restricted_inner[result] {
	firewall := input.document[i].resource.google_compute_firewall[name]
	common_lib.is_ingress(firewall)
	common_lib.is_unrestricted(firewall.source_ranges[_])
	allowed := getAllowed(firewall)
	isRDPport(allowed[a])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_firewall[%s].allow.ports' includes RDP port 3389", [name]), "keyExpectedValue": sprintf("'google_compute_firewall[%s].allow.ports' should not include RDP port 3389", [name]), "resourceName": tf_lib.get_resource_name(firewall, name), "resourceType": "google_compute_firewall", "searchKey": sprintf("google_compute_firewall[%s].allow.ports", [name]), "searchLine": common_lib.build_search_line(["google_compute_firewall", name, "allow", a], [])}
}

getAllowed(firewall) = allowed {
	is_array(firewall.allow)
	allowed := firewall.allow
}

getAllowed(firewall) = allowed {
	is_object(firewall.allow)
	allowed := [firewall.allow]
}

isRDPport(allow) {
	isTCPorUDP(allow.protocol)
	contains(allow.ports[j], "-")
	port_bounds := split(allow.ports[j], "-")
	low_bound := to_number(port_bounds[0])
	high_bound := to_number(port_bounds[1])
	isInBounds(low_bound, high_bound)
} else {
	isTCPorUDP(allow.protocol)
	contains(allow.ports[j], "-") == false
	to_number(allow.ports[j]) == 3389
} else {
	not allow.ports
	isTCPorUDP(allow.protocol)
}

isInBounds(low, high) {
	low <= 3389
	high >= 3389
}

isTCPorUDP(protocol) {
	protocols := {"tcp", "udp", "all"}
	lower(protocol) == protocols[_]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDP Access Is Not Restricted"
# description: >-
#   Check if the Google compute firewall allows unrestricted RDP access. Allowed ports should not contain RDP port 3389
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.rdp_access_is_not_restricted"
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
#       identifier: positive1
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: positive2
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: positive3
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
rdp_access_is_not_restricted_snippet[violation] {
	rdp_access_is_not_restricted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

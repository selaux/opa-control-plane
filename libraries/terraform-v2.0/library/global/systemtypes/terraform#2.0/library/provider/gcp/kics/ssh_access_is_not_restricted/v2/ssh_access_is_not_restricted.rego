package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.ssh_access_is_not_restricted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

ssh_access_is_not_restricted_inner[result] {
	firewall := input.document[i].resource.google_compute_firewall[name]
	common_lib.is_ingress(firewall)
	common_lib.is_unrestricted(firewall.source_ranges[_])
	allowed := getAllowed(firewall)
	ports := isSSHport(allowed[a])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_firewall[%s].allow.ports' includes SSH port 22", [name]), "keyExpectedValue": sprintf("'google_compute_firewall[%s].allow.ports' should not include SSH port 22", [name]), "resourceName": tf_lib.get_resource_name(firewall, name), "resourceType": "google_compute_firewall", "searchKey": sprintf("google_compute_firewall[%s].allow.ports=%s", [name, ports]), "searchLine": common_lib.build_search_line(["google_compute_firewall", name, "allow", a, "ports"], [])}
	# Allow traffic from anywhere

}

getAllowed(firewall) = allowed {
	is_array(firewall.allow)
	allowed := firewall.allow
}

getAllowed(firewall) = allowed {
	is_object(firewall.allow)
	allowed := [firewall.allow]
}

isSSHport(allow) = ports {
	contains(allow.ports[j], "-")
	port_bounds := split(allow.ports[j], "-")
	low_bound := to_number(port_bounds[0])
	high_bound := to_number(port_bounds[1])
	isInBounds(low_bound, high_bound)
	ports := allow.ports[j]
}

isSSHport(allow) = ports {
	contains(allow.ports[j], "-") == false
	to_number(allow.ports[j]) == 22
	ports := allow.ports[j]
}

isSSHport(allow) = ports {
	not allow.ports
	isTCPorAll(allow.protocol)
	ports := "0-65535"
}

isTCPorAll(protocol) {
	protocols := {"tcp", "all"}
	lower(protocol) == protocols[_]
}

isInBounds(low, high) {
	low <= 22
	high >= 22
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SSH Access Is Not Restricted"
# description: >-
#   Google Firewall should not allow SSH access (port 22) from the Internet (public CIDR block) to ensure the principle of least privileges
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.ssh_access_is_not_restricted"
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
ssh_access_is_not_restricted_snippet[violation] {
	ssh_access_is_not_restricted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

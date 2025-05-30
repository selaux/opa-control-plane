package global.systemtypes["terraform:2.0"].library.provider.azure.kics.ssh_is_exposed_to_the_internet.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

ssh_is_exposed_to_the_internet_inner[result] {
	resource := input.document[i].resource.azurerm_network_security_rule[var0]
	upper(resource.access) == "ALLOW"
	upper(resource.direction) == "INBOUND"
	isRelevantProtocol(resource.protocol)
	isRelevantPort(resource.destination_port_range)
	isRelevantAddressPrefix(resource.source_address_prefix)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_network_security_rule.%s.destination_port_range' might be 22", [var0]), "keyExpectedValue": sprintf("'azurerm_network_security_rule.%s.destination_port_range' cannot be 22", [var0]), "resourceName": tf_lib.get_resource_name(resource, var0), "resourceType": "azurerm_network_security_rule", "searchKey": sprintf("azurerm_network_security_rule[%s].destination_port_range", [var0])}
}

isRelevantProtocol(protocol) = allow {
	upper(protocol) != "UDP"
	upper(protocol) != "ICMP"
	allow = true
}

isRelevantPort(port) = allow {
	regex.match("(^|\\s|,)22(-|,|$|\\s)", port)
	allow = true
}

else = allow {
	ports = split(port, ",")
	sublist = split(ports[var], "-")
	to_number(trim(sublist[0], " ")) <= 22
	to_number(trim(sublist[1], " ")) >= 22
	allow = true
}

isRelevantAddressPrefix(prefix) = allow {
	prefix == "*"
	allow = true
}

else = allow {
	prefix == "0.0.0.0"
	allow = true
}

else = allow {
	endswith(prefix, "/0")
	allow = true
}

else = allow {
	prefix == "internet"
	allow = true
}

else = allow {
	prefix == "any"
	allow = true
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SSH Is Exposed To The Internet"
# description: >-
#   Port 22 (SSH) is exposed to the internet
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.ssh_is_exposed_to_the_internet"
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
#     name: "azurerm"
#     versions:
#       min: "v2"
#       max: "v3"
#   rule_targets:
#     - argument: ""
#       identifier: azurerm_network_security_rule
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
ssh_is_exposed_to_the_internet_snippet[violation] {
	ssh_is_exposed_to_the_internet_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

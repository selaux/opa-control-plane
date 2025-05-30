package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sensitive_port_is_exposed_to_wide_private_network.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sensitive_port_is_exposed_to_wide_private_network_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	portContent := common_lib.tcpPortsMap[port]
	portNumber = port
	portName = portContent
	protocol := tf_lib.getProtocolList(resource.ingress.protocol)[_0]
	isPrivateNetwork(resource)
	tf_lib.containsPort(resource.ingress, portNumber)
	isTCPorUDP(protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, portNumber]), "keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, portNumber]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s].ingress", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress"], [])}
}

sensitive_port_is_exposed_to_wide_private_network_inner[result] {
	module := input.document[i].module[name]
	ingressKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_security_group", "ingress_with_cidr_blocks")
	common_lib.valid_key(module, ingressKey)
	portContent := common_lib.tcpPortsMap[port]
	portNumber = port
	portName = portContent
	ingress := module[ingressKey][idx]
	protocol := tf_lib.getProtocolList(ingress.protocol)[_0]
	common_lib.isPrivateIP(ingress.cidr_blocks[_])
	tf_lib.containsPort(ingress, portNumber)
	isTCPorUDP(protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, portNumber]), "keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, portNumber]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, ingressKey]), "searchLine": common_lib.build_search_line(["module", name, ingressKey], [])}
}

isTCPorUDP("TCP") = true

isTCPorUDP("UDP") = true

isPrivateNetwork(resource) {
	some i
	common_lib.isPrivateIP(resource.ingress.cidr_blocks[i])
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Sensitive Port Is Exposed To Wide Private Network"
# description: >-
#   A sensitive port, such as port 23 or port 110, is open for a wide private network in either TCP or UDP protocol
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sensitive_port_is_exposed_to_wide_private_network"
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
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: aws_security_group
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
sensitive_port_is_exposed_to_wide_private_network_snippet[violation] {
	sensitive_port_is_exposed_to_wide_private_network_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

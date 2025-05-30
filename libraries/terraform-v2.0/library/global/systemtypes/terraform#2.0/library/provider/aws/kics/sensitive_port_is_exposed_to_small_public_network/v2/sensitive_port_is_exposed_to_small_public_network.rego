package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sensitive_port_is_exposed_to_small_public_network.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sensitive_port_is_exposed_to_small_public_network_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	portContent := commonLib.tcpPortsMap[port]
	portNumber = port
	portName = portContent
	protocol := tf_lib.getProtocolList(resource.ingress.protocol)[_]
	isSmallPublicNetwork(resource)
	tf_lib.containsPort(resource.ingress, portNumber)
	isTCPorUDP(protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, portNumber]), "keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, portNumber]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s].ingress", [name]), "searchValue": sprintf("%s,%d", [protocol, portNumber])}
}

isTCPorUDP("TCP") = true

isTCPorUDP("UDP") = true

isSmallPublicNetwork(resource) {
	endswith(resource.ingress.cidr_blocks[_], "/25")
} else {
	endswith(resource.ingress.cidr_blocks[_], "/26")
} else {
	endswith(resource.ingress.cidr_blocks[_], "/27")
} else {
	endswith(resource.ingress.cidr_blocks[_], "/28")
} else {
	endswith(resource.ingress.cidr_blocks[_], "/29")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Sensitive Port Is Exposed To Small Public Network"
# description: >-
#   A sensitive port, such as port 23 or port 110, is open for a small public network in either TCP or UDP protocol
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sensitive_port_is_exposed_to_small_public_network"
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
sensitive_port_is_exposed_to_small_public_network_snippet[violation] {
	sensitive_port_is_exposed_to_small_public_network_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

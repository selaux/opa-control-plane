package global.systemtypes["terraform:2.0"].library.provider.aws.kics.unknown_port_exposed_to_internet.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

unknown_port_exposed_to_internet_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	ingress := getIngressList(resource.ingress)
	cidr := ingress[j].cidr_blocks
	unknownPort(ingress[j].from_port, ingress[j].to_port)
	isEntireNetwork(cidr)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_security_group[%s].ingress ports are unknown and exposed to the entire Internet", [name]), "keyExpectedValue": sprintf("aws_security_group[%s].ingress ports are known", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s].ingress.cidr_blocks", [name]), "searchLine": commonLib.build_search_line(["resource", "aws_security_group", name, "ingress", j, "cidr_blocks"], [])}
}

getIngressList(ingress) = list {
	is_array(ingress)
	list := ingress
} else = list {
	is_object(ingress)
	list := [ingress]
} else = null

unknownPort(from_port, to_port) {
	port := numbers.range(from_port, to_port)[i]
	not commonLib.valid_key(commonLib.tcpPortsMap, port)
}

isEntireNetwork(cidr) = allow {
	count({x | cidr[x]; cidr[x] == "0.0.0.0/0"}) != 0
	allow = true
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Unknown Port Exposed To Internet"
# description: >-
#   AWS Security Group should not have an unknown port exposed to the entire Internet
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.unknown_port_exposed_to_internet"
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
unknown_port_exposed_to_internet_snippet[violation] {
	unknown_port_exposed_to_internet_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

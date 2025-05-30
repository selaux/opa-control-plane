package global.systemtypes["terraform:2.0"].library.provider.aws.kics.vpc_without_network_firewall.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

vpc_without_network_firewall_inner[result] {
	resource := input.document[i].resource.aws_vpc[vpcName]
	not with_network_firewall(vpcName)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_vpc[%s] does not have an 'aws_networkfirewall_firewall' associated", [vpcName]), "keyExpectedValue": sprintf("aws_vpc[%s] has an 'aws_networkfirewall_firewall' associated", [vpcName]), "resourceName": vpcName, "resourceType": "aws_vpc", "searchKey": sprintf("aws_vpc[%s]", [vpcName]), "searchLine": common_lib.build_search_line(["resource", "aws_vpc", vpcName], [])}
}

with_network_firewall(vpcName) {
	networkFirewall := input.document[_].resource.aws_networkfirewall_firewall[_]
	split(networkFirewall.vpc_id, ".")[1] == vpcName
}

# METADATA: library-snippet
# version: v1
# title: "KICS: VPC Without Network Firewall"
# description: >-
#   VPC should have a Network Firewall associated
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.vpc_without_network_firewall"
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
#       identifier: aws_vpc
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
vpc_without_network_firewall_snippet[violation] {
	vpc_without_network_firewall_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

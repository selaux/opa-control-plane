package global.systemtypes["terraform:2.0"].library.provider.aws.kics.default_security_groups_with_unrestricted_traffic.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

default_security_groups_with_unrestricted_traffic_inner[result] {
	sg := input.document[i].resource.aws_default_security_group[name]
	checkCidrBlock(sg)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "ingress.cidr_blocks or egress.cidr_blocks are equal to '0.0.0.0/0' or '::/0'", "keyExpectedValue": "ingress.cidr_blocks or egress.cidr_blocks diferent from '0.0.0.0/0' and '::/0'", "resourceName": tf_lib.get_resource_name(sg, name), "resourceType": "aws_db_security_group", "searchKey": sprintf("aws_default_security_group[%s]", [name])}
}

checkCidrBlock(sg) {
	some c
	sg.ingress.cidr_blocks[c] == "0.0.0.0/0"
}

checkCidrBlock(sg) {
	some c
	sg.egress.cidr_blocks[c] == "0.0.0.0/0"
}

checkCidrBlock(sg) {
	some c
	sg.egress.ipv6_cidr_blocks[c] == "::/0"
}

checkCidrBlock(sg) {
	some c
	sg.ingress.ipv6_cidr_blocks[c] == "::/0"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Default Security Groups With Unrestricted Traffic"
# description: >-
#   Check if default security group does not restrict all inbound and outbound traffic.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.default_security_groups_with_unrestricted_traffic"
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
#       identifier: aws_db_security_group
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
default_security_groups_with_unrestricted_traffic_snippet[violation] {
	default_security_groups_with_unrestricted_traffic_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

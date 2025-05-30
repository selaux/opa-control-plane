package global.systemtypes["terraform:2.0"].library.provider.aws.kics.vpc_peering_route_table_with_unrestricted_cidr.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

vpc_peering_route_table_with_unrestricted_cidr_inner[result] {
	resource := input.document[i].resource.aws_route[name]
	common_lib.valid_key(resource, "vpc_peering_connection_id")
	open_cidr(resource)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_route[%s] does not restrict CIDR", [name]), "keyExpectedValue": sprintf("aws_route[%s] restricts CIDR", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_route", "searchKey": sprintf("aws_route[%s]", [name])}
}

vpc_peering_route_table_with_unrestricted_cidr_inner[result] {
	resource := input.document[i].resource.aws_route_table[name]
	route_table_open_cidr(resource.route)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_route[%s].route does not restrict CIDR", [name]), "keyExpectedValue": sprintf("aws_route[%s].route restricts CIDR", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_route", "searchKey": sprintf("aws_route[%s].route", [name])}
}

openCidrs := {"cidr_block": "0.0.0.0/0", "ipv6_cidr_block": "::/0", "destination_cidr_block": "0.0.0.0/0", "destination_ipv6_cidr_block": "::/0"}

open_cidr(resource) {
	resource[x] == openCidrs[x]
} else {
	routeTableName := split(resource.route_table_id, ".")[1]
	routeTable := input.document[_].resource.aws_route_table[routeTableName]

	unrestricted(routeTable.route)
}

unrestricted(route) {
	is_array(route)
	route[r][x] == openCidrs[x]
} else {
	is_object(route)
	route[x] == openCidrs[x]
}

route_table_open_cidr(route) {
	is_array(route)
	common_lib.valid_key(route[r], "vpc_peering_connection_id")
	unrestricted(route)
} else {
	is_object(route)
	common_lib.valid_key(route, "vpc_peering_connection_id")
	unrestricted(route)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: VPC Peering Route Table with Unrestricted CIDR"
# description: >-
#   VPC Peering Route Table should restrict CIDR
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.vpc_peering_route_table_with_unrestricted_cidr"
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
vpc_peering_route_table_with_unrestricted_cidr_snippet[violation] {
	vpc_peering_route_table_with_unrestricted_cidr_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

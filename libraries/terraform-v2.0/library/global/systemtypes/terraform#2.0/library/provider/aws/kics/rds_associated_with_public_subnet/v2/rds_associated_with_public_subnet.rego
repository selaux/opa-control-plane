package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rds_associated_with_public_subnet.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rds_associated_with_public_subnet_inner[result] {
	db := input.document[i].resource.aws_db_instance[name]
	subnetGroupName := get_name(db.db_subnet_group_name)
	sg := input.document[_].resource.aws_db_subnet_group[subnetGroupName]
	subnets := sg.subnet_ids
	is_public(subnets)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "RDS is running in a public subnet", "keyExpectedValue": "RDS should not be running in a public subnet", "resourceName": tf_lib.get_resource_name(db, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].db_subnet_group_name", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "db_subnet_group_name"], [])}
	# get subnet group name

	# get subnet group

	# get subnets info

	# verify if some subnet is public

}

options := {"${aws_db_subnet_group", "${aws_subnet"}

get_name(nameValue) = name {
	contains(nameValue, options[_])
	name := split(nameValue, ".")[1]
} else = name {
	op := options[_]
	not contains(nameValue, options[op])
	name := nameValue
}

unrestricted_cidr(sb) {
	sb.cidr_block == "0.0.0.0/0"
} else {
	sb.ipv6_cidr_block == "::/0"
}

is_public(subnets) {
	subnet := subnets[_]
	subnetName := get_name(subnet)
	sb := input.document[_].resource.aws_subnet[subnetName]
	unrestricted_cidr(sb)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDS Associated with Public Subnet"
# description: >-
#   RDS should not run in public subnet
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rds_associated_with_public_subnet"
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
#       identifier: aws_db_instance
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
rds_associated_with_public_subnet_snippet[violation] {
	rds_associated_with_public_subnet_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

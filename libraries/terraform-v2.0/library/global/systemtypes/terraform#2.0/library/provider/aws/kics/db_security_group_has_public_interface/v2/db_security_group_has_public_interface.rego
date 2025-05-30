package global.systemtypes["terraform:2.0"].library.provider.aws.kics.db_security_group_has_public_interface.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

db_security_group_has_public_interface_inner[result] {
	resource := input.document[i].resource.aws_db_security_group[name]
	cidrs := {"0.0.0.0/0", "::/0"}
	cidrValue := cidrs[_0]
	resource.ingress.cidr == cidrValue
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_db_security_group[%s].ingress.cidr' is '%s'", [name, resource.ingress.cidr]), "keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress.cidr' should not be '0.0.0.0/0' or '::/0'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_security_group", "searchKey": sprintf("aws_db_security_group[%s].ingress.cidr", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_security_group", name, "ingress", "cidr"], [])}
}

db_security_group_has_public_interface_inner[result] {
	resource := input.document[i].resource.aws_db_security_group[name]
	cidrs := {"0.0.0.0/0", "::/0"}
	cidrValue := cidrs[_0]
	resource.ingress[idx].cidr == cidrValue
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' is '%s'", [name, idx, resource.ingress[idx].cidr]), "keyExpectedValue": sprintf("'aws_db_security_group[%s].ingress[%d].cidr' should not be '0.0.0.0/0' or '::/0'", [name, idx]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_security_group", "searchKey": sprintf("aws_db_security_group[%s].ingress.cidr", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_security_group", name, "ingress", idx, "cidr"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DB Security Group Has Public Interface"
# description: >-
#   The CIDR IP should not be a public interface
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.db_security_group_has_public_interface"
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
db_security_group_has_public_interface_snippet[violation] {
	db_security_group_has_public_interface_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

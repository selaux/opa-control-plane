package global.systemtypes["terraform:2.0"].library.provider.aws.kics.vpc_subnet_assigns_public_ip.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

vpc_subnet_assigns_public_ip_inner[result] {
	resource := input.document[i].resource.aws_subnet[name]
	resource.map_public_ip_on_launch == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_subnet[%s].map_public_ip_on_launch is set to true", [name]), "keyExpectedValue": sprintf("aws_subnet[%s].map_public_ip_on_launch should be set to false or undefined", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_subnet", "searchKey": sprintf("aws_subnet[%s].map_public_ip_on_launch", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_subnet", name, "map_public_ip_on_launch"], [])}
}

vpc_subnet_assigns_public_ip_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_subnet", "map_public_ip_on_launch")
	module[keyToCheck] == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s.%s is set to true", [name, keyToCheck]), "keyExpectedValue": sprintf("%s.%s should be set to false", [name, keyToCheck]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("%s.%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck], [])}
}

vpc_subnet_assigns_public_ip_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_subnet", "map_public_ip_on_launch")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s.map_public_ip_on_launch is set undefined", [name]), "keyExpectedValue": sprintf("%s.map_public_ip_on_launch should be set to false", [name]), "remediation": sprintf("%s = false", [keyToCheck]), "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("%s", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: VPC Subnet Assigns Public IP"
# description: >-
#   VPC Subnet should not assign public IP
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.vpc_subnet_assigns_public_ip"
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
#       identifier: aws_subnet
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
vpc_subnet_assigns_public_ip_snippet[violation] {
	vpc_subnet_assigns_public_ip_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

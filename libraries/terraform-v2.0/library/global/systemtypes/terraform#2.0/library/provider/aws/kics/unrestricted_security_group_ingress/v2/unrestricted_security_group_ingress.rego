package global.systemtypes["terraform:2.0"].library.provider.aws.kics.unrestricted_security_group_ingress.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

unrestricted_security_group_ingress_inner[result] {
	rule := input.document[i].resource.aws_security_group_rule[name]
	lower(rule.type) == "ingress"
	some j
	contains(rule.cidr_blocks[j], "0.0.0.0/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'rule.cidr_blocks' is equal '0.0.0.0/0'", "keyExpectedValue": "One of 'rule.cidr_blocks' not equal '0.0.0.0/0'", "resourceName": tf_lib.get_resource_name(rule, name), "resourceType": "aws_security_group_rule", "searchKey": sprintf("aws_security_group_rule[%s].cidr_blocks", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group_rule", name, "cidr_blocks"], [])}
}

unrestricted_security_group_ingress_inner[result] {
	ingrs := input.document[i].resource.aws_security_group[name].ingress
	some j
	contains(ingrs.cidr_blocks[j], "0.0.0.0/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'ingress.cidr_blocks' equal '0.0.0.0/0'", "keyExpectedValue": "One of 'ingress.cidr_blocks' not equal '0.0.0.0/0'", "resourceName": tf_lib.get_resource_name(input.document[i].resource.aws_security_group[name], name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s].ingress.cidr_blocks", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group_rule", name, "ingress", "cidr_blocks"], [])}
}

unrestricted_security_group_ingress_inner[result] {
	ingrs := input.document[i].resource.aws_security_group[name].ingress[j]
	contains(ingrs.cidr_blocks[idx], "0.0.0.0/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'ingress.cidr_blocks' equal '0.0.0.0/0'", "keyExpectedValue": "One of 'ingress.cidr_blocks' not equal '0.0.0.0/0'", "resourceName": tf_lib.get_resource_name(input.document[i].resource.aws_security_group[name], name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", j, "cidr_blocks", idx], [])}
}

# rule for modules
unrestricted_security_group_ingress_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_security_group_rule", "ingress_cidr_blocks")
	cidr := module[keyToCheck][idxCidr]
	contains(cidr, "0.0.0.0/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'ingress.cidr_blocks' equal '0.0.0.0/0'", "keyExpectedValue": "One of 'ingress.cidr_blocks' not equal '0.0.0.0/0'", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, "ingress_cidr_blocks", idxCidr], [])}
	# based on module terraform-aws-modules/security-group/aws

}

unrestricted_security_group_ingress_inner[result] {
	rule := input.document[i].resource.aws_security_group_rule[name]
	lower(rule.type) == "ingress"
	some j
	contains(rule.ipv6_cidr_blocks[j], "::/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'rule.ipv6_cidr_blocks' is equal '::/0'", "keyExpectedValue": "One of 'rule.ipv6_cidr_blocks' should not be equal to '::/0'", "resourceName": tf_lib.get_resource_name(rule, name), "resourceType": "aws_security_group_rule", "searchKey": sprintf("aws_security_group_rule[%s].ipv6_cidr_blocks", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group_rule", name, "ipv6_cidr_blocks"], [])}
}

unrestricted_security_group_ingress_inner[result] {
	ingrs := input.document[i].resource.aws_security_group[name].ingress
	some j
	contains(ingrs.ipv6_cidr_blocks[j], "::/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'ingress.ipv6_cidr_blocks' is equal '::/0'", "keyExpectedValue": "One of 'ingress.ipv6_cidr_blocks' should not be equal to '::/0'", "resourceName": tf_lib.get_resource_name(input.document[i].resource.aws_security_group[name], name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s].ingress.ipv6_cidr_blocks", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group_rule", name, "ingress", "ipv6_cidr_blocks"], [])}
}

unrestricted_security_group_ingress_inner[result] {
	ingrs := input.document[i].resource.aws_security_group[name].ingress[j]
	contains(ingrs.ipv6_cidr_blocks[idx], "::/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'ingress.ipv6_cidr_blocks' is equal '::/0'", "keyExpectedValue": "One of 'ingress.ipv6_cidr_blocks' should not be equal to '::/0'", "resourceName": tf_lib.get_resource_name(input.document[i].resource.aws_security_group[name], name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress", j, "ipv6_cidr_blocks", idx], [])}
}

# rule for modules
unrestricted_security_group_ingress_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_security_group_rule", "ingress_ipv6_cidr_blocks")
	cidr := module[keyToCheck][idxCidr]
	contains(cidr, "::/0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'ingress.ipv6_cidr_blocks' is equal '::/0'", "keyExpectedValue": "One of 'ingress.ipv6_cidr_blocks' should not be equal to '::/0'", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, "ingress_ipv6_cidr_blocks", idxCidr], [])}
	# based on module terraform-aws-modules/security-group/aws

}

# METADATA: library-snippet
# version: v1
# title: "KICS: Unrestricted Security Group Ingress"
# description: >-
#   Security groups allow ingress from 0.0.0.0:0 and/or ::/0
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.unrestricted_security_group_ingress"
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
#     - argument: ""
#       identifier: aws_security_group_rule
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
unrestricted_security_group_ingress_snippet[violation] {
	unrestricted_security_group_ingress_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

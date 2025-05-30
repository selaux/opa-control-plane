package global.systemtypes["terraform:2.0"].library.provider.aws.kics.network_acl_with_unrestricted_access_to_rdp.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

network_acl_with_unrestricted_access_to_rdp_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_network_acl[name]
	is_array(resource.ingress)
	tf_lib.portOpenToInternet(resource.ingress[idx], 3389)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_network_acl[%s].ingress[%d] 'RDP' (TCP:3389) is public", [name, idx]), "keyExpectedValue": sprintf("aws_network_acl[%s].ingress[%d] 'RDP' (TCP:3389) should not be public", [name, idx]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_network_acl", "searchKey": sprintf("aws_network_acl[%s].ingress", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_network_acl", name, "ingress", idx], [])}
}

network_acl_with_unrestricted_access_to_rdp_inner[result] {
	doc := input.document[i]
	net_acl := doc.resource.aws_network_acl[netAclName]
	net_acl_rule := doc.resource.aws_network_acl_rule[netAclRuleName]
	split(net_acl_rule.network_acl_id, ".")[1] == netAclName
	tf_lib.portOpenToInternet(net_acl_rule, 3389)
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_network_acl[%s] 'RDP' (TCP:3389) is public", [netAclRuleName]), "keyExpectedValue": sprintf("aws_network_acl[%s] 'RDP' (TCP:3389) should not be public", [netAclRuleName]), "resourceName": netAclRuleName, "resourceType": "aws_network_acl_rule", "searchKey": sprintf("aws_network_acl_rule[%s]", [netAclRuleName]), "searchLine": common_lib.build_search_line(["resource", "aws_network_acl_rule", netAclRuleName], [])}
}

network_acl_with_unrestricted_access_to_rdp_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_network_acl[name]
	not is_array(resource.ingress)
	tf_lib.portOpenToInternet(resource.ingress, 3389)
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_network_acl[%s].ingress 'RDP' (TCP:3389) is public", [name]), "keyExpectedValue": sprintf("aws_network_acl[%s].ingress 'RDP' (TCP:3389) should not be public", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_network_acl", "searchKey": sprintf("aws_network_acl[%s].ingress", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_network_acl", name, "ingress"], [])}
}

network_acl_with_unrestricted_access_to_rdp_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_default_vpc", "default_network_acl_ingress")
	common_lib.valid_key(module, keyToCheck)
	rule := module[keyToCheck][idx]
	tf_lib.portOpenToInternet(rule, 3389)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("module[%s].%s[%d] 'RDP' (TCP:3389) is public", [name, keyToCheck, idx]), "keyExpectedValue": sprintf("module[%s].%s[%d] 'RDP' (TCP:3389) should not be public", [name, keyToCheck, idx]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck, idx], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Network ACL With Unrestricted Access To RDP"
# description: >-
#   'RDP' (TCP:3389) should not be public in AWS Network ACL
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.network_acl_with_unrestricted_access_to_rdp"
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
#       identifier: aws_network_acl
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_network_acl_rule
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
network_acl_with_unrestricted_access_to_rdp_snippet[violation] {
	network_acl_with_unrestricted_access_to_rdp_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

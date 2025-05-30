package global.systemtypes["terraform:2.0"].library.provider.aws.kics.vpc_default_security_group_accepts_all_traffic.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

blocks := {"ingress", "egress"}

vpc_default_security_group_accepts_all_traffic_inner[result] {
	resource := input.document[i].resource.aws_default_security_group[name]
	common_lib.valid_key(resource, "vpc_id")
	block := blocks[b]
	common_lib.valid_key(resource, block)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_default_security_group[{{%s}}] has '%s' defined", [name, block]), "keyExpectedValue": sprintf("aws_default_security_group[{{%s}}] should not have '%s' defined", [name, block]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_default_security_group", "searchKey": sprintf("aws_default_security_group[{{%s}}].%s", [name, block])}
}

vpc_default_security_group_accepts_all_traffic_inner[result] {
	resource := input.document[i].resource.aws_default_security_group[name]
	common_lib.valid_key(resource, "vpc_id")
	block := blocks[b]
	cidrs := {"cidr_blocks", "ipv6_cidr_blocks"}
	acceptAll := {"0.0.0.0/0", "::/0"}
	rules := resource[block][_]
	cidr := rules[cidrs[c]][_]
	cidr == acceptAll[a]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'%s' accepts all traffic", [block]), "keyExpectedValue": sprintf("'%s' should be undefined", [block]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_default_security_group", "searchKey": sprintf("aws_default_security_group[{{%s}}].%s.%s", [name, block, cidrs[c]])}
	# ingress or egress

	# ingress.cidr_blocks or ingress.ipv6_cidr_blocks or egress.cidr_blocks or egress.ipv6_cidr_blocks

}

# METADATA: library-snippet
# version: v1
# title: "KICS: VPC Default Security Group Accepts All Traffic"
# description: >-
#   Default Security Group attached to every VPC should restrict all traffic
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.vpc_default_security_group_accepts_all_traffic"
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
#       identifier: aws_default_security_group
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
vpc_default_security_group_accepts_all_traffic_snippet[violation] {
	vpc_default_security_group_accepts_all_traffic_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

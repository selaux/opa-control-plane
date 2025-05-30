package global.systemtypes["terraform:2.0"].library.provider.aws.kics.security_groups_not_used.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

security_groups_not_used_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_security_group[securityGroupName]
	not is_used(securityGroupName, doc, resource)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_security_group[%s]' is not used", [securityGroupName]), "keyExpectedValue": sprintf("'aws_security_group[%s]' should be used", [securityGroupName]), "resourceName": tf_lib.get_resource_name(resource, securityGroupName), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s]", [securityGroupName])}
}

is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
	securityGroupUsed := value.security_groups[_]
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}

# check in modules for module terraform-aws-modules/security-group/aws
is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
	securityGroupUsed := value.security_group_id
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}

# check security groups assigned to aws_instance resources
is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
	securityGroupUsed := value.vpc_security_group_ids[_]
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}

# check security groups assigned to aws_eks_cluster resources
is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
	securityGroupUsed := value.vpc_config.security_group_ids[_]
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}

is_used(securityGroupName, doc, resource) {
	sec_group_used := resource.name
	[path, value] := walk(doc)
	securityGroupUsed := value.security_groups[_]
	sec_group_used == securityGroupUsed
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Security Group Not Used"
# description: >-
#   Security group must be used or not declared
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.security_groups_not_used"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
security_groups_not_used_snippet[violation] {
	security_groups_not_used_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

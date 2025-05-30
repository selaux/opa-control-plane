package global.systemtypes["terraform:2.0"].library.provider.aws.kics.security_group_with_unrestricted_access_to_ssh.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

security_group_with_unrestricted_access_to_ssh_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	tf_lib.portOpenToInternet(resource.ingress, 22)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_security_group[%s] 'SSH' (Port:22) is public", [name]), "keyExpectedValue": sprintf("aws_security_group[%s] 'SSH' (Port:22) should not be public", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s].ingress.cidr_blocks", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, "ingress.cidr_blocks"], [])}
}

security_group_with_unrestricted_access_to_ssh_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_security_group", "ingress_cidr_blocks")
	tf_lib.portOpenToInternet(module.ingress, 22)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'SSH' (Port:22) is public", "keyExpectedValue": "'SSH' (Port:22) should not be public", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].ingress.cidr_blocks", [name]), "searchLine": common_lib.build_search_line(["module", name, "ingress", "cidr_blocks"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Security Group With Unrestricted Access To SSH"
# description: >-
#   'SSH' (TCP:22) should not be public in AWS Security Group
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.security_group_with_unrestricted_access_to_ssh"
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
security_group_with_unrestricted_access_to_ssh_snippet[violation] {
	security_group_with_unrestricted_access_to_ssh_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

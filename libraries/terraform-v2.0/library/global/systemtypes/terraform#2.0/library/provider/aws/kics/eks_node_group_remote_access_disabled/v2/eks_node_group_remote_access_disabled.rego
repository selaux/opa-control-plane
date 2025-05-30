package global.systemtypes["terraform:2.0"].library.provider.aws.kics.eks_node_group_remote_access_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

eks_node_group_remote_access_disabled_inner[result] {
	doc := input.document[i]
	eksNodeGroup := doc.resource.aws_eks_node_group[name]
	remoteAccess := eksNodeGroup.remote_access
	common_lib.valid_key(remoteAccess, "ec2_ssh_key")
	not common_lib.valid_key(remoteAccess, "source_security_groups_ids")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_eks_node_group[%s].remote_access.source_security_groups_ids' is undefined or null", [name]), "keyExpectedValue": sprintf("'aws_eks_node_group[%s].remote_access.source_security_groups_ids' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(eksNodeGroup, name), "resourceType": "aws_eks_node_group", "searchKey": sprintf("aws_eks_node_group[%s].remote_access", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EKS node group remote access disabled"
# description: >-
#   EKS node group remote access is disabled when 'SourceSecurityGroups' is missing
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.eks_node_group_remote_access_disabled"
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
#       identifier: aws_eks_node_group
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
eks_node_group_remote_access_disabled_snippet[violation] {
	eks_node_group_remote_access_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

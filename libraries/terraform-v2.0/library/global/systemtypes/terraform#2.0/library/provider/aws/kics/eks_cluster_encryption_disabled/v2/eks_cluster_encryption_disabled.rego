package global.systemtypes["terraform:2.0"].library.provider.aws.kics.eks_cluster_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

eks_cluster_encryption_disabled_inner[result] {
	cluster := input.document[i].resource.aws_eks_cluster[name]
	not common_lib.valid_key(cluster, "encryption_config")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'encryption_config' is undefined or null", "keyExpectedValue": "'encryption_config' should be defined and not null", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "aws_eks_cluster", "searchKey": sprintf("aws_eks_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_eks_cluster", name], [])}
}

eks_cluster_encryption_disabled_inner[result] {
	cluster := input.document[i].resource.aws_eks_cluster[name]
	resources := cluster.encryption_config.resources
	count({x | resource := resources[x]; resource == "secrets"}) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'secrets' is undefined", "keyExpectedValue": "'secrets' should be defined", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "aws_eks_cluster", "searchKey": sprintf("aws_eks_cluster[%s].encryption_config.resources", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_eks_cluster", name, "resources"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EKS Cluster Encryption Disabled"
# description: >-
#   EKS Cluster should be encrypted
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.eks_cluster_encryption_disabled"
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
#       identifier: aws_eks_cluster
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
eks_cluster_encryption_disabled_snippet[violation] {
	eks_cluster_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

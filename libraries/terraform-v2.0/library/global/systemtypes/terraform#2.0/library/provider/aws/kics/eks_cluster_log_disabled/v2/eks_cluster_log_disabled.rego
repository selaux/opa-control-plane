package global.systemtypes["terraform:2.0"].library.provider.aws.kics.eks_cluster_log_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

eks_cluster_log_disabled_inner[result] {
	required_log_types_set = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
	cluster := input.document[i].resource.aws_eks_cluster[name]
	not common_lib.valid_key(cluster, "enabled_cluster_log_types")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'enabled_cluster_log_types' is undefined or null", "keyExpectedValue": "'enabled_cluster_log_types' should be defined and not null", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "aws_eks_cluster", "searchKey": sprintf("aws_eks_cluster[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EKS cluster logging is not enabled"
# description: >-
#   Amazon EKS control plane logging is not enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.eks_cluster_log_disabled"
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
eks_cluster_log_disabled_snippet[violation] {
	eks_cluster_log_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

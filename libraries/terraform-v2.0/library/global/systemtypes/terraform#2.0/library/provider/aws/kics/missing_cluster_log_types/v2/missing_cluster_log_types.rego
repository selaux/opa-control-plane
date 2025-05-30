package global.systemtypes["terraform:2.0"].library.provider.aws.kics.missing_cluster_log_types.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

missing_cluster_log_types_inner[result] {
	required_log_types_set = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
	logs := input.document[i].resource.aws_eks_cluster[name].enabled_cluster_log_types
	existing_log_types_set := {x | x = logs[_]}
	existing_log_types_set & existing_log_types_set != required_log_types_set
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'enabled_cluster_log_types' has missing log types", "keyExpectedValue": "'enabled_cluster_log_types' has all log types", "resourceName": tf_lib.get_resource_name(input.document[i].resource.aws_eks_cluster[name], name), "resourceType": "aws_eks_cluster", "searchKey": sprintf("aws_eks_cluster[%s].enabled_cluster_log_types", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Missing Cluster Log Types"
# description: >-
#   Amazon EKS control plane logging don't enabled for all log types
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.missing_cluster_log_types"
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
missing_cluster_log_types_snippet[violation] {
	missing_cluster_log_types_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

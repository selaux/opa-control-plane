package global.systemtypes["terraform:2.0"].library.provider.aws.kics.eks_cluster_has_public_access.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

eks_cluster_has_public_access_inner[result] {
	resource := input.document[i].resource.aws_eks_cluster[name]
	resource.vpc_config.endpoint_public_access == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'vpc_config.endpoint_public_access' is equal 'true'", "keyExpectedValue": "'vpc_config.endpoint_public_access' should equal 'false'", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_eks_cluster", "searchKey": sprintf("aws_eks_cluster[%s].vpc_config.endpoint_public_access", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_eks_cluster", name, "vpc_config", "endpoint_public_access"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EKS Cluster Has Public Access"
# description: >-
#   Amazon EKS public endpoint shoud be set to false
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.eks_cluster_has_public_access"
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
eks_cluster_has_public_access_snippet[violation] {
	eks_cluster_has_public_access_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

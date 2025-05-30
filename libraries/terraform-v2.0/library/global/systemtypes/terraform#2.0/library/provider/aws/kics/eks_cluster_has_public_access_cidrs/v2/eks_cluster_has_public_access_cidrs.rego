package global.systemtypes["terraform:2.0"].library.provider.aws.kics.eks_cluster_has_public_access_cidrs.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

eks_cluster_has_public_access_cidrs_inner[result] {
	resource := input.document[i].resource.aws_eks_cluster[name]
	resource.vpc_config.endpoint_public_access == true
	resource.vpc_config.public_access_cidrs[_] == "0.0.0.0/0"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'vpc_config.public_access_cidrs' is equal '0.0.0.0/0'", "keyExpectedValue": "One of 'vpc_config.public_access_cidrs' not equal '0.0.0.0/0'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_eks_cluster", "searchKey": sprintf("aws_eks_cluster[%s].vpc_config.public_access_cidrs", [name])}
}

#default vaule of cidrs is "0.0.0.0/0"
eks_cluster_has_public_access_cidrs_inner[result] {
	resource := input.document[i].resource.aws_eks_cluster[name]
	resource.vpc_config.endpoint_public_access == true
	not resource.vpc_config.public_access_cidrs
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'vpc_config.public_access_cidrs' is missing", "keyExpectedValue": "'vpc_config.public_access_cidrs' should exist", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_eks_cluster", "searchKey": sprintf("aws_eks_cluster[%s].vpc_config.public_access_cidrs", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EKS Cluster Has Public Access CIDRs"
# description: >-
#   Amazon EKS public endpoint is enables and accessible to all: 0.0.0.0/0"
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.eks_cluster_has_public_access_cidrs"
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
eks_cluster_has_public_access_cidrs_snippet[violation] {
	eks_cluster_has_public_access_cidrs_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.redshift_cluster_without_vpc.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

redshift_cluster_without_vpc_inner[result] {
	resource := input.document[i].resource.aws_redshift_cluster[name]
	attributes := {"cluster_subnet_group_name", "vpc_security_group_ids"}
	attr := attributes[_]
	not common_lib.valid_key(resource, attr)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_redshift_cluster[%s].%s is undefined", [name, attr]), "keyExpectedValue": sprintf("aws_redshift_cluster[%s].%s should be set", [name, attr]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s]", [name]), "searchValue": sprintf("%s", [attr])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redshift Cluster Without VPC"
# description: >-
#   Redshift Cluster should be configured in VPC (Virtual Private Cloud)
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.redshift_cluster_without_vpc"
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
#       identifier: aws_redshift_cluster
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
redshift_cluster_without_vpc_snippet[violation] {
	redshift_cluster_without_vpc_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

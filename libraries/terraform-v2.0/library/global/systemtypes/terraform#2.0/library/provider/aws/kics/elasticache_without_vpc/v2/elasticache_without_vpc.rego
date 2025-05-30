package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticache_without_vpc.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticache_without_vpc_inner[result] {
	resource := input.document[i].resource.aws_elasticache_cluster[name]
	not common_lib.valid_key(resource, "subnet_group_name")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_elasticache_cluster[%s].subnet_group_name' is undefined or null", [name]), "keyExpectedValue": sprintf("'aws_elasticache_cluster[%s].subnet_group_name' should be defined and not null'", [name]), "resourceName": tf_lib.get_specific_resource_name(resource, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElastiCache Without VPC"
# description: >-
#   ElastiCache should be launched in a Virtual Private Cloud (VPC)
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticache_without_vpc"
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
#       identifier: aws_elasticache_cluster
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
elasticache_without_vpc_snippet[violation] {
	elasticache_without_vpc_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

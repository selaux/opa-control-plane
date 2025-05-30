package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticache_nodes_not_created_across_multi_az.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticache_nodes_not_created_across_multi_az_inner[result] {
	cluster := input.document[i].resource.aws_elasticache_cluster[name]
	lower(cluster.engine) == "memcached"
	to_number(cluster.num_cache_nodes) > 1
	not cluster.az_mode
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'az_mode' is undefined", "keyExpectedValue": "'az_mode' should be set and must be 'cross-az' in multi nodes cluster", "remediation": "az_mode = \"cross-az\"", "remediationType": "addition", "resourceName": tf_lib.get_specific_resource_name(cluster, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name], [])}
}

elasticache_nodes_not_created_across_multi_az_inner[result] {
	cluster := input.document[i].resource.aws_elasticache_cluster[name]
	lower(cluster.engine) == "memcached"
	to_number(cluster.num_cache_nodes) > 1
	lower(cluster.az_mode) != "cross-az"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'az_mode' is '%s'", [cluster.az_mode]), "keyExpectedValue": "'az_mode' should be 'cross-az' in multi nodes cluster", "remediation": json.marshal({"after": "cross-az", "before": sprintf("%s", [cluster.az_mode])}), "remediationType": "replacement", "resourceName": tf_lib.get_specific_resource_name(cluster, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s].az_mode", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name, "az_mode"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElastiCache Nodes Not Created Across Multi AZ"
# description: >-
#   ElastiCache Nodes should be created across multi az, which means 'az_mode' should be set to 'cross-az' in multi nodes cluster
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticache_nodes_not_created_across_multi_az"
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
elasticache_nodes_not_created_across_multi_az_snippet[violation] {
	elasticache_nodes_not_created_across_multi_az_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticache_redis_cluster_without_backup.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticache_redis_cluster_without_backup_inner[result] {
	cluster := input.document[i].resource.aws_elasticache_cluster[name]
	cluster.engine == "redis"
	not common_lib.valid_key(cluster, "snapshot_retention_limit")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'snapshot_retention_limit' is undefined", "keyExpectedValue": "'snapshot_retention_limit' should be higher than 0", "remediation": "snapshot_retention_limit = 5", "remediationType": "addition", "resourceName": tf_lib.get_specific_resource_name(cluster, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name], [])}
}

elasticache_redis_cluster_without_backup_inner[result] {
	cluster := input.document[i].resource.aws_elasticache_cluster[name]
	cluster.engine == "redis"
	cluster.snapshot_retention_limit = 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'snapshot_retention_limit' is 0", "keyExpectedValue": "'snapshot_retention_limit' should be higher than 0", "remediation": json.marshal({"after": "5", "before": "0"}), "remediationType": "replacement", "resourceName": tf_lib.get_specific_resource_name(cluster, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s].snapshot_retention_limit", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name, "snapshot_retention_limit"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElastiCache Redis Cluster Without Backup"
# description: >-
#   ElastiCache Redis cluster should have 'snapshot_retention_limit' higher than 0
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticache_redis_cluster_without_backup"
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
elasticache_redis_cluster_without_backup_snippet[violation] {
	elasticache_redis_cluster_without_backup_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

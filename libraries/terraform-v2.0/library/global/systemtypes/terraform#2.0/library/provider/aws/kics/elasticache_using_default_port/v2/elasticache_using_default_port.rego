package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticache_using_default_port.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticache_using_default_port_inner[result] {
	resource := input.document[i].resource.aws_elasticache_cluster[name]
	not common_lib.valid_key(resource, "port")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_elasticache_cluster.port is undefined or null", "keyExpectedValue": "aws_elasticache_cluster.port should be defined and not null", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name], [])}
}

elasticache_using_default_port_inner[result] {
	cluster := input.document[i].resource.aws_elasticache_cluster[name]
	engines := {"memcached": 11211, "redis": 6379}
	enginePort := engines[e]
	cluster.engine == e
	cluster.port == enginePort
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'port' is set to %d", [enginePort]), "keyExpectedValue": sprintf("'port' should not be set to %d", [enginePort]), "resourceName": tf_lib.get_specific_resource_name(cluster, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s].port", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name, "port"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElastiCache Using Default Port"
# description: >-
#   ElastiCache should not use the default port (an attacker can easily guess the port). For engine set to Redis, the default port is 6379. The Memcached default port is 11211
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticache_using_default_port"
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
elasticache_using_default_port_snippet[violation] {
	elasticache_using_default_port_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

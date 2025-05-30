package global.systemtypes["terraform:2.0"].library.provider.aws.kics.redis_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

redis_disabled_inner[result] {
	resource := input.document[i].resource.aws_elasticache_cluster[name]
	resource.engine != "redis"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_elasticache_cluster[%s].engine doesn't enable Redis", [name]), "keyExpectedValue": sprintf("resource.aws_elasticache_cluster[%s].engine should have Redis enabled", [name]), "remediation": json.marshal({"after": "redis", "before": "memcached"}), "remediationType": "replacement", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("resource.aws_elasticache_cluster[%s].engine", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_cluster", name, "engine"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redis Disabled"
# description: >-
#   ElastiCache should have Redis enabled, since it covers Compliance Certifications such as FedRAMP, HIPAA, and PCI DSS. For more information, take a look at 'https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SelectEngine.html'
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.redis_disabled"
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
redis_disabled_snippet[violation] {
	redis_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

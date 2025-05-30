package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticache_replication_group_not_encrypted_at_rest.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticache_replication_group_not_encrypted_at_rest_inner[result] {
	resource := input.document[i].resource.aws_elasticache_replication_group[name]
	not common_lib.valid_key(resource, "at_rest_encryption_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "The attribute 'at_rest_encryption_enabled' is undefined", "keyExpectedValue": "The attribute 'at_rest_encryption_enabled' should be set to true", "remediation": "at_rest_encryption_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_elasticache_replication_group", "searchKey": sprintf("aws_elasticache_replication_group[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_replication_group", name], [])}
}

elasticache_replication_group_not_encrypted_at_rest_inner[result] {
	resource := input.document[i].resource.aws_elasticache_replication_group[name]
	resource.at_rest_encryption_enabled != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "The attribute 'at_rest_encryption_enabled' is not set to true", "keyExpectedValue": "The attribute 'at_rest_encryption_enabled' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_elasticache_replication_group", "searchKey": sprintf("aws_elasticache_replication_group[%s].at_rest_encryption_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticache_replication_group", name, "at_rest_encryption_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElastiCache Replication Group Not Encrypted At Rest"
# description: >-
#   ElastiCache Replication Group encryption should be enabled at Rest
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticache_replication_group_not_encrypted_at_rest"
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
#       identifier: aws_elasticache_replication_group
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
elasticache_replication_group_not_encrypted_at_rest_snippet[violation] {
	elasticache_replication_group_not_encrypted_at_rest_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

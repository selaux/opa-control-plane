package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rds_cluster_with_backup_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rds_cluster_with_backup_disabled_inner[result] {
	resource := input.document[i].resource.aws_rds_cluster[name]
	not common_lib.valid_key(resource, "backup_retention_period")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_rds_cluster.backup_retention_period is undefined or null", "keyExpectedValue": "aws_rds_cluster.backup_retention_period should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_rds_cluster", "searchKey": sprintf("aws_rds_cluster[{{%s}}]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDS Cluster With Backup Disabled"
# description: >-
#   RDS Cluster backup retention period should be specifically defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rds_cluster_with_backup_disabled"
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
rds_cluster_with_backup_disabled_snippet[violation] {
	rds_cluster_with_backup_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

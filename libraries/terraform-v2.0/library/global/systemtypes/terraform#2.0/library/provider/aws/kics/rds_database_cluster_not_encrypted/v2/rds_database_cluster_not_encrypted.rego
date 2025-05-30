package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rds_database_cluster_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rds_database_cluster_not_encrypted_inner[result] {
	rds := input.document[i].resource.aws_db_cluster_snapshot[name]
	db := rds.db_cluster_identifier
	dbName := split(db, ".")[1]
	not rds_cluster_encrypted(dbName)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_db_cluster_snapshot.db_cluster_identifier' is not encrypted", "keyExpectedValue": "aws_db_cluster_snapshot.db_cluster_identifier' should be encrypted", "resourceName": tf_lib.get_resource_name(rds, name), "resourceType": "aws_db_cluster_snapshot", "searchKey": sprintf("aws_db_cluster_snapshot[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_cluster_snapshot", name], [])}
}

rds_cluster_encrypted(rdsName) {
	rds := input.document[i].resource.aws_rds_cluster[rdsName]
	rds.storage_encrypted == true
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDS Database Cluster not Encrypted"
# description: >-
#   RDS Database Cluster Encryption should be enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rds_database_cluster_not_encrypted"
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
#       identifier: aws_db_cluster_snapshot
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
rds_database_cluster_not_encrypted_snippet[violation] {
	rds_database_cluster_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

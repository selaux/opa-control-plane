package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rds_storage_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rds_storage_not_encrypted_inner[result] {
	cluster := input.document[i].resource.aws_rds_cluster[name]
	not is_serverless(cluster)
	not common_lib.valid_key(cluster, "storage_encrypted")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_rds_cluster.storage_encrypted is undefined", "keyExpectedValue": "aws_rds_cluster.storage_encrypted should be set to true", "remediation": "storage_encrypted = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "aws_rds_cluster", "searchKey": sprintf("aws_rds_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_rds_cluster", name], [])}
}

rds_storage_not_encrypted_inner[result] {
	cluster := input.document[i].resource.aws_rds_cluster[name]
	cluster.storage_encrypted != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_rds_cluster.storage_encrypted is set to false", "keyExpectedValue": "aws_rds_cluster.storage_encrypted should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "aws_rds_cluster", "searchKey": sprintf("aws_rds_cluster[%s].storage_encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_rds_cluster", name, "storage_encrypted"], [])}
}

is_serverless(cluster) {
	cluster.engine_mode == "serverless"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDS Storage Not Encrypted"
# description: >-
#   RDS Storage should be encrypted, which means the attribute 'storage_encrypted' should be set to 'true'
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rds_storage_not_encrypted"
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
#       identifier: aws_rds_cluster
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
rds_storage_not_encrypted_snippet[violation] {
	rds_storage_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

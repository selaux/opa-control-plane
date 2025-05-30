package global.systemtypes["terraform:2.0"].library.provider.aws.kics.docdb_cluster_encrypted_with_aws_managed_key.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

docdb_cluster_encrypted_with_aws_managed_key_inner[result] {
	resource := input.document[i].resource.aws_docdb_cluster[name]
	tf_lib.uses_aws_managed_key(resource.kms_key_id, "alias/aws/rds")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "DOCDB Cluster is encrypted with AWS managed key", "keyExpectedValue": "DOCDB Cluster should not be encrypted with AWS managed key", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_docdb_cluster", "searchKey": sprintf("aws_docdb_cluster[%s].kms_key_id", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DOCDB Cluster Encrypted With AWS Managed Key"
# description: >-
#   DOCDB Cluster should be encrypted with customer-managed KMS keys instead of AWS managed keys
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.docdb_cluster_encrypted_with_aws_managed_key"
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
docdb_cluster_encrypted_with_aws_managed_key_snippet[violation] {
	docdb_cluster_encrypted_with_aws_managed_key_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

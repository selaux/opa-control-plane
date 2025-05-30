package global.systemtypes["terraform:2.0"].library.provider.aws.kics.docdb_cluster_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

docdb_cluster_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_docdb_cluster[name]
	not common_lib.valid_key(resource, "storage_encrypted")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_docdb_cluster.storage_encrypted is missing", "keyExpectedValue": "aws_docdb_cluster.storage_encrypted should be set to true", "remediation": "storage_encrypted = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_docdb_cluster", "searchKey": sprintf("aws_docdb_cluster[{{%s}}]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name], [])}
}

docdb_cluster_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_docdb_cluster[name]
	resource.storage_encrypted == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_docdb_cluster.storage_encrypted is set to false", "keyExpectedValue": "aws_docdb_cluster.storage_encrypted should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_docdb_cluster", "searchKey": sprintf("aws_docdb_cluster[{{%s}}].storage_encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name, "storage_encrypted"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DOCDB Cluster Not Encrypted"
# description: >-
#   AWS DOCDB Cluster storage should be encrypted
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.docdb_cluster_not_encrypted"
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
#       identifier: aws_docdb_cluster
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
docdb_cluster_not_encrypted_snippet[violation] {
	docdb_cluster_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

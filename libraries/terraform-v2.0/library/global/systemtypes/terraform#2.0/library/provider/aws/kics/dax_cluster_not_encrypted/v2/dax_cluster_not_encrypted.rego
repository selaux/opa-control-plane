package global.systemtypes["terraform:2.0"].library.provider.aws.kics.dax_cluster_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

dax_cluster_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_dax_cluster[name]
	resource.server_side_encryption.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_dax_cluster.server_side_encryption.enabled is set to false", "keyExpectedValue": "aws_dax_cluster.server_side_encryption.enabled should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_dax_cluster", "searchKey": sprintf("aws_dax_cluster[{{%s}}].server_side_encryption.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_dax_cluster", name, "server_side_encryption", "enabled"], [])}
}

dax_cluster_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_dax_cluster[name]
	not common_lib.valid_key(resource, "server_side_encryption")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_dax_cluster.server_side_encryption is missing", "keyExpectedValue": "aws_dax_cluster.server_side_encryption.enabled should be set to true", "remediation": "server_side_encryption {\n\t\tenabled = true\n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_dax_cluster", "searchKey": sprintf("aws_dax_cluster[{{%s}}]", [name])}
}

dax_cluster_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_dax_cluster[name]
	common_lib.valid_key(resource, "server_side_encryption")
	not common_lib.valid_key(resource.server_side_encryption, "enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_dax_cluster.server_side_encryption.enabled is missing", "keyExpectedValue": "aws_dax_cluster.server_side_encryption.enabled should be set to true", "remediation": "enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_dax_cluster", "searchKey": sprintf("aws_dax_cluster[{{%s}}].server_side_encryption", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DAX Cluster Not Encrypted"
# description: >-
#   AWS DAX Cluster should have server-side encryption at rest
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.dax_cluster_not_encrypted"
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
#       identifier: aws_dax_cluster
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
dax_cluster_not_encrypted_snippet[violation] {
	dax_cluster_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

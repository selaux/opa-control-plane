package global.systemtypes["terraform:2.0"].library.provider.aws.kics.redshift_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

redshift_not_encrypted_inner[result] {
	cluster := input.document[i].resource.aws_redshift_cluster[name]
	not common_lib.valid_key(cluster, "encrypted")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_redshift_cluster.encrypted is undefined or null", "keyExpectedValue": "aws_redshift_cluster.encrypted should be defined and not null", "remediation": "encrypted = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name], [])}
}

redshift_not_encrypted_inner[result] {
	cluster := input.document[i].resource.aws_redshift_cluster[name]
	cluster.encrypted == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_redshift_cluster.encrypted is true", "keyExpectedValue": "aws_redshift_cluster.encrypted should be set to false", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s].encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name, "encrypted"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redshift Not Encrypted"
# description: >-
#   AWS Redshift Cluster should be encrypted. Check if 'encrypted' field is false or undefined (default is false)
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.redshift_not_encrypted"
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
#       identifier: aws_redshift_cluster
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
redshift_not_encrypted_snippet[violation] {
	redshift_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

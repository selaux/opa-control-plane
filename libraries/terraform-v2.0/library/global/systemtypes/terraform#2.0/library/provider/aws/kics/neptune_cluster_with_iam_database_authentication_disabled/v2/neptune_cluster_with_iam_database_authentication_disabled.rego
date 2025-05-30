package global.systemtypes["terraform:2.0"].library.provider.aws.kics.neptune_cluster_with_iam_database_authentication_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

neptune_cluster_with_iam_database_authentication_disabled_inner[result] {
	password_policy := input.document[i].resource.aws_neptune_cluster[name]
	not common_lib.valid_key(password_policy, "iam_database_authentication_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'iam_database_authentication_enabled' is undefined", "keyExpectedValue": "'iam_database_authentication_enabled' should be set to true", "remediation": "iam_database_authentication_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(password_policy, name), "resourceType": "aws_neptune_cluster", "searchKey": sprintf("aws_neptune_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_neptune_cluster", name], [])}
}

neptune_cluster_with_iam_database_authentication_disabled_inner[result] {
	password_policy := input.document[i].resource.aws_neptune_cluster[name]
	password_policy.iam_database_authentication_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'iam_database_authentication_enabled' is set to false", "keyExpectedValue": "'iam_database_authentication_enabled' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(password_policy, name), "resourceType": "aws_neptune_cluster", "searchKey": sprintf("aws_neptune_cluster[%s].iam_database_authentication_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_neptune_cluster", name, "iam_database_authentication_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Neptune Cluster With IAM Database Authentication Disabled"
# description: >-
#   Neptune Cluster should have IAM Database Authentication enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.neptune_cluster_with_iam_database_authentication_disabled"
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
#       identifier: aws_neptune_cluster
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
neptune_cluster_with_iam_database_authentication_disabled_snippet[violation] {
	neptune_cluster_with_iam_database_authentication_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

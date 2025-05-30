package global.systemtypes["terraform:2.0"].library.provider.aws.kics.neptune_cluster_instance_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

neptune_cluster_instance_is_publicly_accessible_inner[result] {
	neptuneClusterInstance := input.document[i].resource.aws_neptune_cluster_instance[name]
	neptuneClusterInstance.publicly_accessible == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_neptune_cluster_instance[%s].publicly_accessible is set to true", [name]), "keyExpectedValue": sprintf("aws_neptune_cluster_instance[%s].publicly_accessible should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(neptuneClusterInstance, name), "resourceType": "aws_neptune_cluster_instance", "searchKey": sprintf("aws_neptune_cluster_instance[%s].publicly_accessible", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_neptune_cluster_instance", name, "publicly_accessible"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Neptune Cluster Instance is Publicly Accessible"
# description: >-
#   Neptune Cluster Instance should not be publicly accessible
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.neptune_cluster_instance_is_publicly_accessible"
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
#       identifier: aws_neptune_cluster_instance
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
neptune_cluster_instance_is_publicly_accessible_snippet[violation] {
	neptune_cluster_instance_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

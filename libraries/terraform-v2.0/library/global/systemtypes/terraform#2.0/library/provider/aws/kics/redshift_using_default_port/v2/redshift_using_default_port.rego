package global.systemtypes["terraform:2.0"].library.provider.aws.kics.redshift_using_default_port.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

redshift_using_default_port_inner[result] {
	redshift := input.document[i].resource.aws_redshift_cluster[name]
	not common_lib.valid_key(redshift, "port")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_redshift_cluster.port is undefined or null", "keyExpectedValue": "aws_redshift_cluster.port should be defined and not null", "resourceName": tf_lib.get_resource_name(redshift, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name], [])}
}

redshift_using_default_port_inner[result] {
	redshift := input.document[i].resource.aws_redshift_cluster[name]
	redshift.port == 5439
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_redshift_cluster.port is set to 5439", "keyExpectedValue": "aws_redshift_cluster.port should not be set to 5439", "resourceName": tf_lib.get_resource_name(redshift, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s].port", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name, "port"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redshift Using Default Port"
# description: >-
#   Redshift should not use the default port (5439) because an attacker can easily guess the port
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.redshift_using_default_port"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
redshift_using_default_port_snippet[violation] {
	redshift_using_default_port_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

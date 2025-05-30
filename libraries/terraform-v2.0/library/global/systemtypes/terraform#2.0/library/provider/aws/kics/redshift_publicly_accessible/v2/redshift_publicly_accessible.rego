package global.systemtypes["terraform:2.0"].library.provider.aws.kics.redshift_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

redshift_publicly_accessible_inner[result] {
	public := input.document[i].resource.aws_redshift_cluster[name]
	not common_lib.valid_key(public, "publicly_accessible")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_redshift_cluster.publicly_accessible is undefined or null", "keyExpectedValue": "aws_redshift_cluster.publicly_accessible should be defined and not null", "remediation": "publicly_accessible = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(public, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s]", [name])}
}

redshift_publicly_accessible_inner[result] {
	public := input.document[i].resource.aws_redshift_cluster[name]
	public.publicly_accessible == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_redshift_cluster.publicly_accessible is true", "keyExpectedValue": "aws_redshift_cluster.publicly_accessible should be set to false", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(public, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s].publicly_accessible", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redshift Publicly Accessible"
# description: >-
#   AWS Redshift Clusters must not be publicly accessible. Check if 'publicly_accessible' field is true or undefined (default is true)
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.redshift_publicly_accessible"
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
redshift_publicly_accessible_snippet[violation] {
	redshift_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

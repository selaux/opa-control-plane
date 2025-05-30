package global.systemtypes["terraform:2.0"].library.provider.aws.kics.batch_job_definition_with_privileged_container_properties.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

batch_job_definition_with_privileged_container_properties_inner[result] {
	document := input.document[i]
	properties_json = document.resource.aws_batch_job_definition[name].container_properties
	properties := json.unmarshal(properties_json)
	properties.privileged == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_batch_job_definition[%s].container_properties.privileged is 'true'", [name]), "keyExpectedValue": sprintf("aws_batch_job_definition[%s].container_properties.privileged should be 'false' or not set", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(document.resource.aws_batch_job_definition[name], name), "resourceType": "aws_batch_job_definition", "searchKey": sprintf("aws_batch_job_definition[%s].container_properties.privileged", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_batch_job_definition", name, "container_properties", "privileged"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Batch Job Definition With Privileged Container Properties"
# description: >-
#   Batch Job Definition should not have Privileged Container Properties
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.batch_job_definition_with_privileged_container_properties"
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
#       identifier: aws_batch_job_definition
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
batch_job_definition_with_privileged_container_properties_snippet[violation] {
	batch_job_definition_with_privileged_container_properties_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

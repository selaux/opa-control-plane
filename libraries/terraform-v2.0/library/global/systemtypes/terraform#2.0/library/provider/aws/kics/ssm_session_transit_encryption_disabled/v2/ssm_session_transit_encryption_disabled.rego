package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ssm_session_transit_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ssm_session_transit_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_ssm_document[name]
	resource.document_type == "Session"
	content := common_lib.json_unmarshal(resource.content)
	not common_lib.valid_key(content, "inputs")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'inputs' is undefined or null", "keyExpectedValue": "'inputs' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ssm_document", "searchKey": sprintf("aws_ssm_document[%s].content", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ssm_document", name, "content"], [])}
}

ssm_session_transit_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_ssm_document[name]
	resource.document_type == "Session"
	content := common_lib.json_unmarshal(resource.content)
	not common_lib.valid_key(content.inputs, "kmsKeyId")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'inputs.kmsKeyId' is undefined or null", "keyExpectedValue": "'inputs.kmsKeyId' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ssm_document", "searchKey": sprintf("aws_ssm_document[%s].content", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ssm_document", name, "content"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SSM Session Transit Encryption Disabled"
# description: >-
#   SSM Session should be encrypted in transit
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ssm_session_transit_encryption_disabled"
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
#       identifier: aws_ssm_document
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
ssm_session_transit_encryption_disabled_snippet[violation] {
	ssm_session_transit_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

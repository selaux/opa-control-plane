package global.systemtypes["terraform:2.0"].library.provider.aws.kics.kms_key_with_no_deletion_window.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

kms_key_with_no_deletion_window_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	resource.is_enabled == true
	resource.enable_key_rotation == true
	not resource.deletion_window_in_days
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_kms_key[%s].deletion_window_in_days is undefined", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].deletion_window_in_days should be set and valid", [name]), "remediation": "deletion_window_in_days = 30", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_kms_key", name], [])}
}

kms_key_with_no_deletion_window_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	resource.is_enabled == true
	resource.enable_key_rotation == true
	resource.deletion_window_in_days > 30
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_kms_key[%s].deletion_window_in_days is set but invalid", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].deletion_window_in_days should be set and valid", [name]), "remediation": json.marshal({"after": "30", "before": sprintf("%d", [resource.deletion_window_in_days])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s].deletion_window_in_days", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_kms_key", name, "deletion_window_in_days"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: KMS Key With No Deletion Window"
# description: >-
#   AWS KMS Key should have a valid deletion window
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.kms_key_with_no_deletion_window"
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
#       identifier: aws_kms_key
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
kms_key_with_no_deletion_window_snippet[violation] {
	kms_key_with_no_deletion_window_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

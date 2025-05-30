package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cmk_rotation_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cmk_rotation_disabled_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	not key_set_to_false(resource)
	not common_lib.valid_key(resource, "enable_key_rotation")
	customer_master_key_spec_set_to_symmetric(resource)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_kms_key[%s].enable_key_rotation is undefined", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].enable_key_rotation should be set to true", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s]", [name])}
}

cmk_rotation_disabled_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	not key_set_to_false(resource)
	resource.enable_key_rotation == true
	not customer_master_key_spec_set_to_symmetric(resource)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_kms_key[%s].enable_key_rotation is true", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].enable_key_rotation should be set to false", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s]", [name])}
}

cmk_rotation_disabled_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	not key_set_to_false(resource)
	resource.enable_key_rotation == false
	customer_master_key_spec_set_to_symmetric(resource)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_kms_key[%s].enable_key_rotation is false", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].enable_key_rotation should be set to true", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s]", [name])}
}

customer_master_key_spec_set_to_symmetric(resource) {
	resource.customer_master_key_spec == "SYMMETRIC_DEFAULT"
} else {
	not common_lib.valid_key(resource, "customer_master_key_spec")
}

key_set_to_false(resource) {
	resource.is_enabled == false
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CMK Rotation Disabled"
# description: >-
#   Customer Master Keys (CMK) must have rotation enabled, which means the attribute 'enable_key_rotation' must be set to 'true' when the key is enabled.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cmk_rotation_disabled"
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
cmk_rotation_disabled_snippet[violation] {
	cmk_rotation_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

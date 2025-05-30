package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cmk_is_unusable.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cmk_is_unusable_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	resource.is_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_kms_key[%s].is_enabled is set to false", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].is_enabled should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s].is_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_kms_key", name, "is_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CMK Is Unusable"
# description: >-
#   AWS Key Management Service (KMS) must only possess usable Customer Master Keys (CMK), which means the CMKs must have the attribute 'is_enabled' set to true
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cmk_is_unusable"
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
cmk_is_unusable_snippet[violation] {
	cmk_is_unusable_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

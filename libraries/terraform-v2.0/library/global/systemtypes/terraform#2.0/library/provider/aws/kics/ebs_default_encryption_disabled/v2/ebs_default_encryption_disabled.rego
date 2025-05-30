package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ebs_default_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ebs_default_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_ebs_encryption_by_default[name]
	resource.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'aws_ebs_encryption_by_default.encrypted' is false", "keyExpectedValue": "'aws_ebs_encryption_by_default.encrypted' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ebs_encryption_by_default", "searchKey": sprintf("aws_ebs_encryption_by_default[%s].enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ebs_encryption_by_default", name, "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EBS Default Encryption Disabled"
# description: >-
#   EBS Encryption should be enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ebs_default_encryption_disabled"
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
#       identifier: aws_ebs_encryption_by_default
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
ebs_default_encryption_disabled_snippet[violation] {
	ebs_default_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

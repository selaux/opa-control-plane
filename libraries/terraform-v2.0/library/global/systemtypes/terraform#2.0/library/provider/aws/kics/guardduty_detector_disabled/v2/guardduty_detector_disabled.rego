package global.systemtypes["terraform:2.0"].library.provider.aws.kics.guardduty_detector_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

guardduty_detector_disabled_inner[result] {
	awsGuardDuty := input.document[i].resource.aws_guardduty_detector[name]
	detector := awsGuardDuty.enable
	detector == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "GuardDuty Detector is not Enabled", "keyExpectedValue": "GuardDuty Detector should be Enabled", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(awsGuardDuty, name), "resourceType": "aws_guardduty_detector", "searchKey": sprintf("aws_guardduty_detector[%s].enable", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_guardduty_detector", name, "enable"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: GuardDuty Detector Disabled"
# description: >-
#   Make sure that Amazon GuardDuty is Enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.guardduty_detector_disabled"
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
#       identifier: aws_guardduty_detector
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
guardduty_detector_disabled_snippet[violation] {
	guardduty_detector_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

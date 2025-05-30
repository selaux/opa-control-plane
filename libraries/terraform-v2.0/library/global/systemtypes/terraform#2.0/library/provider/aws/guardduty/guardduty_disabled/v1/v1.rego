package global.systemtypes["terraform:2.0"].library.provider.aws.guardduty.guardduty_disabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: GuardDuty: Block GuardDuty organization with disabled GuardDuty detector"
# description: Require GuardDuty Detector to be enabled for a GuardDuty Organiztion.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-guardduty"
# custom:
#   id: "aws.guardduty.guardduty_disabled"
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
#     - { scope: "resource", service: "guardduty", name: "guardduty_detector", identifier: "aws_guardduty_detector", argument: "enable" }
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
prohibit_guardduty_organization_configuration_without_detector_enabled[violation] {
	block_disabled_guardduty_detector[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

block_disabled_guardduty_detector[obj] {
	guardduty_detector := util.guardduty_detector_resource_changes[_]
	guardduty_detector.change.after.enable != true

	obj := {
		"message": sprintf("Disabled GuardDuty Detector %v in module %v is prohibited.", [guardduty_detector.address]),
		"resource": guardduty_detector,
		"context": {"enable": guardduty_detector.change.after.enable},
	}
}

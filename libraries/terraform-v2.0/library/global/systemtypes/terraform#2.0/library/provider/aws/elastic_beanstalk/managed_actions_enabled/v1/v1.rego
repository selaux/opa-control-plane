package global.systemtypes["terraform:2.0"].library.provider.aws.elastic_beanstalk.managed_actions_enabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Elastic Beanstalk: Prohibit the Elastic beanstalk environments with disabled managed actions"
# description: Require AWS/Elastic Beanstalk environments to have the managed actions setting enabled.
# severity: "high"
# platform: "terraform"
# resource-type: "aws-elastic_beanstalk"
# custom:
#   id: "aws.elastic_beanstalk.managed_actions_enabled"
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
#     - { scope: "resource", service: "elastic_beanstalk", name: "elastic_beanstalk_environment", identifier: "aws_elastic_beanstalk_environment", argument: "setting" }
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
disabled_managed_actions_is_prohibited[violation] {
	managed_actions_disabled_prohibited[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

managed_actions_disabled_prohibited[obj] {
	elastic_beanstalk_environment := util.elastic_beanstalk_environment_resource_changes[_]
	setting := elastic_beanstalk_environment.change.after.setting[_]
	setting.name == "ManagedActionsEnabled"
	setting.value == "false"

	obj := {
		"message": sprintf("Beanstalk environment %v with managed actions disabled is prohibited.", [elastic_beanstalk_environment.address]),
		"resource": elastic_beanstalk_environment,
		"context": {"setting.name": "ManagedActionsEnabled", "setting.value": "false"},
	}
}

managed_actions_disabled_prohibited[obj] {
	elastic_beanstalk_environment := util.elastic_beanstalk_environment_resource_changes[_]
	setting := elastic_beanstalk_environment.change.after.setting[_]
	setting.name == "ManagedActionsEnabled"
	setting.value == false

	obj := {
		"message": sprintf("Beanstalk environment %v with managed actions disabled is prohibited.", [elastic_beanstalk_environment.address]),
		"resource": elastic_beanstalk_environment,
		"context": {"setting.name": "ManagedActionsEnabled", "setting.value": false},
	}
}

managed_actions_disabled_prohibited[obj] {
	setting_block := util.elastic_beanstalk_environment_resource_changes[_]
	not is_setting_present(setting_block)

	obj := {
		"message": sprintf("Beanstalk Environment %v does not have the 'ManagedActionsEnabled' setting.", [setting_block.address]),
		"resource": setting_block,
		"context": {"setting.name": "ManagedActionsEnabled", "setting.value": "undefined"},
	}
}

is_setting_present(setting_block) {
	setting_block.change.after.setting[_].name == "ManagedActionsEnabled"
}

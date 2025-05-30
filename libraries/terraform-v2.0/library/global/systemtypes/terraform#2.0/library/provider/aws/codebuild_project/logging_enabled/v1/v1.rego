package global.systemtypes["terraform:2.0"].library.provider.aws.codebuild_project.logging_enabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: CodeBuild Project: Prohibit if logging is not configured"
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-codebuild_project"
# description: Require CodeBuild Projects to have 'logs_config' with either s3_logs or 'cloudwatch_logs' enabled.
# custom:
#   id: "aws.codebuild_project.logging_enabled"
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
#     - { scope: "resource", service: "codebuild", "name": "codebuild_project", identifier: "aws_codebuild_project", argument: "logs_config.s3_logs.status" }
#     - { scope: "resource", service: "codebuild", "name": "codebuild_project", identifier: "aws_codebuild_project", argument: "logs_config.cloudwatch_logs.status" }
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
codebuild_project_logging_enabled_check[violation] {
	logging_enabled_check[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

logging_enabled_check[obj] {
	cbp := util.codebuild_project_resource_changes[_]

	count(cbp.change.after.logs_config) == 0

	obj := {
		"message": sprintf("AWS CodeBuild Project %v should have the 'logs_config' block defined.", [cbp.address]),
		"resource": cbp,
		"context": {"logs_config": "undefined"},
	}
}

logging_enabled_check[obj] {
	cbp := util.codebuild_project_resource_changes[_]

	cbp.change.after.logs_config[_].s3_logs[_].status == "DISABLED"

	obj := {
		"message": sprintf("AWS CodeBuild Project %v has 'logs_config' with `s3_logs` disabled", [cbp.address]),
		"resource": cbp,
		"context": {"logs_config.s3_logs.status": "DISABLED"},
	}
}

logging_enabled_check[obj] {
	cbp := util.codebuild_project_resource_changes[_]

	cbp.change.after.logs_config[_].cloudwatch_logs[_].status == "DISABLED"

	obj := {
		"message": sprintf("AWS CodeBuild Project %v has 'logs_config' with 'cloudwatch_logs' disabled", [cbp.address]),
		"resource": cbp,
		"context": {"logs_config.cloudwatch_logs.status": "DISABLED"},
	}
}

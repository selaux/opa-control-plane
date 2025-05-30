package global.systemtypes["terraform:2.0"].library.provider.aws.codebuild_project.privileged_check.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Codebuild Project: Prohibit Privileged Mode enabled."
# description: Require CodeBuild Projects environment config to have 'privileged_mode' set to false.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-codebuild_project"
# custom:
#   id: "aws.codebuild_project.privileged_check"
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
#     - { scope: "resource", service: "codebuild", "name": "codebuild_project", identifier: "aws_codebuild_project", argument: "environment.privileged_mode" }
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
codebuild_project_privileged_check[violation] {
	privileged_check[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

privileged_check[obj] {
	cbp := util.codebuild_project_resource_changes[_]
	cbp.change.after.environment[_].privileged_mode == true

	obj := {
		"message": sprintf("CodeBuild Project %v should have privilieged_mode set to false.", [cbp.address]),
		"resource": cbp,
		"context": {"environment.privileged_mode": true},
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.ssm.restrict_public_access.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: SSM: Prohibit publicly accessible SSM documents"
# description: AWS/SSM Document not to be publicly accessible.
# severity: "critical"
# platform: "terraform"
# resource-type: "aws-ssm"
# custom:
#   id: "aws.ssm.restrict_public_access"
#   impact: ""
#   remediation: ""
#   severity: "critical"
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
#     - { scope: "resource", service: "ssm", name: "ssm_document", identifier: "aws_ssm_document", argument: "permissions.account_ids" }
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
prohibit_publicly_accessible_ssm_document[violation] {
	insecure_ssm_document[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_ssm_document[obj] {
	ssm_document := util.ssm_document_resource_changes[_]
	ssm_document.change.after.permissions.account_ids == "All"

	obj := {
		"message": sprintf("Publicly accessible SSM Document %v is prohibited.", [ssm_document.address]),
		"resource": ssm_document,
		"context": {"permissions.account_ids": ssm_document.change.after.permissions.account_ids},
	}
}

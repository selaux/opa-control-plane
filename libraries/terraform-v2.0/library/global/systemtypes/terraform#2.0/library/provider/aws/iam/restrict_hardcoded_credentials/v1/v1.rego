package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_hardcoded_credentials.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: IAM: Restrict hardcoded secret credentials."
# description: Hardcoding of AWS 'access_key' and 'secret_key' in Terraform files is prohibited.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-iam"
# custom:
#   id: "aws.iam.restrict_hardcoded_credentials"
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
#     - { scope: "provider", provider: "aws", argument: "access_key" }
#     - { scope: "provider", provider: "aws", argument: "secret_key" }
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
restrict_hardcoded_credentials[violation] {
	hardcoded_credentials[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

hardcoded_credentials[obj] {
	utils.is_key_defined(input.configuration.provider_config.aws.expressions, "secret_key")

	obj := {
		"message": "Hardcoding of AWS credentials (secret_key) in Terraform files is prohibited.",
		"resource": {
			"type": "provider",
			"address": "configuration.provider_config.aws",
			"name": "aws",
			"change": {"actions": "no-op"},
		},
		"context": {"secret_key": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
	}
}

hardcoded_credentials[obj] {
	utils.is_key_defined(input.configuration.provider_config.aws.expressions, "access_key")

	obj := {
		"message": "Hardcoding of AWS credentials (access_key) in Terraform files is prohibited.",
		"resource": {
			"type": "provider",
			"address": "configuration.provider_config.aws",
			"name": "aws",
			"change": {"actions": "no-op"},
		},
		"context": {"access_key": "XXXXXXXXXXXXXXXXXXXX"},
	}
}

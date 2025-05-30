package global.systemtypes["terraform:2.0"].library.provider.aws.iam.iam_password_policy_aws_foundational_security_best_practices.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: IAM: Ensure IAM account password policy meets AWS Foundational Security Best Practices"
# description: >-
#   Require AWS/IAM account to have complex and unique password policy. As recommended by
#   https://docs.aws.amazon.com/config/latest/developerguide/iam-password-policy.html
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-iam"
# custom:
#   id: "aws.iam.iam_password_policy_aws_foundational_security_best_practices"
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
#     - { scope: "resource", service: "iam", name: "account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_lowercase_characters" }
#     - { scope: "resource", service: "iam", name: "account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_numbers" }
#     - { scope: "resource", service: "iam", name: "account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_symbols" }
#     - { scope: "resource", service: "iam", name: "account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_uppercase_characters" }
#     - { scope: "resource", service: "iam", name: "account_password_policy", identifier: "aws_iam_account_password_policy", argument: "minimum_password_length" }
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
strict_iam_password_policy[violation] {
	iam_password_policy[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	resource.change.after.require_lowercase_characters == false

	violation := {
		"message": sprintf("IAM account password policy %v has 'require_lowercase_characters' as false.", [resource.address]),
		"resource": resource,
		"context": {"require_lowercase_characters": resource.change.after.require_lowercase_characters},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(resource.change.after, "require_lowercase_characters")

	violation := {
		"message": sprintf("IAM account password policy %v does not have 'require_lowercase_characters' defined", [resource.address]),
		"resource": resource,
		"context": {"require_lowercase_characters": "undefined"},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	resource.change.after.require_numbers == false

	violation := {
		"message": sprintf("IAM account password policy %v has 'require_numbers' as false.", [resource.address]),
		"resource": resource,
		"context": {"require_numbers": resource.change.after.require_numbers},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(resource.change.after, "require_numbers")

	violation := {
		"message": sprintf("IAM account password policy %v does not have 'require_numbers' defined", [resource.address]),
		"resource": resource,
		"context": {"require_numbers": "undefined"},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	resource.change.after.require_symbols == false

	violation := {
		"message": sprintf("IAM account password policy %v has 'require_symbols' as false.", [resource.address]),
		"resource": resource,
		"context": {"require_symbols": resource.change.after.require_symbols},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(resource.change.after, "require_symbols")

	violation := {
		"message": sprintf("IAM account password policy %v does not have 'require_symbols' defined", [resource.address]),
		"resource": resource,
		"context": {"require_symbols": "undefined"},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	resource.change.after.require_uppercase_characters == false

	violation := {
		"message": sprintf("IAM account password policy %v has 'require_uppercase_characters' as false.", [resource.address]),
		"resource": resource,
		"context": {"require_uppercase_characters": resource.change.after.require_uppercase_characters},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(resource.change.after, "require_uppercase_characters")

	violation := {
		"message": sprintf("IAM account password policy %v does not have 'require_uppercase_characters' defined", [resource.address]),
		"resource": resource,
		"context": {"require_uppercase_characters": "undefined"},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	resource.change.after.minimum_password_length < 14

	violation := {
		"message": sprintf("IAM account password policy %v has 'minimum_password_length' less than 14 characters.", [resource.address]),
		"resource": resource,
		"context": {"minimum_password_length": resource.change.after.minimum_password_length},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(resource.change.after, "minimum_password_length")

	violation := {
		"message": sprintf("IAM account password policy %v does not have 'minimum_password_length' defined", [resource.address]),
		"resource": resource,
		"context": {"minimum_password_length": "undefined"},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	resource.change.after.password_reuse_prevention < 24

	violation := {
		"message": sprintf("IAM account password policy %v has 'password_reuse_prevention' less than 24.", [resource.address]),
		"resource": resource,
		"context": {"password_reuse_prevention": resource.change.after.password_reuse_prevention},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(resource.change.after, "password_reuse_prevention")

	violation := {
		"message": sprintf("IAM account password policy %v does not have 'password_reuse_prevention' defined", [resource.address]),
		"resource": resource,
		"context": {"password_reuse_prevention": "undefined"},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	resource.change.after.max_password_age > 90

	violation := {
		"message": sprintf("IAM account password policy %v has 'max_password_age' less than 90.", [resource.address]),
		"resource": resource,
		"context": {"max_password_age": resource.change.after.max_password_age},
	}
}

iam_password_policy[violation] {
	resource := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(resource.change.after, "max_password_age")

	violation := {
		"message": sprintf("IAM account password policy %v does not have 'max_password_age' defined", [resource.address]),
		"resource": resource,
		"context": {"max_password_age": "undefined"},
	}
}

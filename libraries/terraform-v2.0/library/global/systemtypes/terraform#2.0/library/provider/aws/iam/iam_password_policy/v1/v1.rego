package global.systemtypes["terraform:2.0"].library.provider.aws.iam.iam_password_policy.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: IAM: Ensure IAM account has Complex and Unique password policy"
# description: >-
#   Require AWS/IAM account to have complex and unique password policy. As recommended by
#   https://attack.mitre.org/techniques/T1110/  the standards here are based off of those established in
#   https://pages.nist.gov/800-63-3/sp800-63b.html#appA and
#   https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=6234434
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-iam"
# custom:
#   id: "aws.iam.iam_password_policy"
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
#     - { scope: "resource", service: "iam", name: "iam_account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_lowercase_characters" }
#     - { scope: "resource", service: "iam", name: "iam_account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_numbers" }
#     - { scope: "resource", service: "iam", name: "iam_account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_symbols" }
#     - { scope: "resource", service: "iam", name: "iam_account_password_policy", identifier: "aws_iam_account_password_policy", argument: "require_uppercase_characters" }
#     - { scope: "resource", service: "iam", name: "iam_account_password_policy", identifier: "aws_iam_account_password_policy", argument: "minimum_password_length" }
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

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	iam_passwd.change.after.require_lowercase_characters == false

	obj := {
		"message": sprintf("IAM account password policy %v has 'require_lowercase_characters' as false.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_lowercase_characters": iam_passwd.change.after.require_lowercase_characters},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	iam_passwd.change.after.require_numbers == false

	obj := {
		"message": sprintf("IAM account password policy %v has 'require_numbers' as false.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_numbers": iam_passwd.change.after.require_numbers},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	iam_passwd.change.after.require_symbols == false

	obj := {
		"message": sprintf("IAM account password policy %v has 'require_symbols' as false.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_symbols": iam_passwd.change.after.require_symbols},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	iam_passwd.change.after.require_uppercase_characters == false

	obj := {
		"message": sprintf("IAM account password policy %v has 'require_uppercase_characters' as false.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_uppercase_characters": iam_passwd.change.after.require_uppercase_characters},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	iam_passwd.change.after.minimum_password_length < 12

	obj := {
		"message": sprintf("IAM account password policy %v has 'minimum_password_length' less than 12 characters.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"minimum_password_length": iam_passwd.change.after.minimum_password_length},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(iam_passwd.change.after, "require_lowercase_characters")

	obj := {
		"message": sprintf("IAM account password policy %v does not contain 'require_lowercase_characters'.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_lowercase_characters": "undefined"},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(iam_passwd.change.after, "require_numbers")

	obj := {
		"message": sprintf("IAM account password policy %v does not contain 'require_numbers'.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_numbers": "undefined"},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(iam_passwd.change.after, "require_symbols")

	obj := {
		"message": sprintf("IAM account password policy %v does not contain 'require_symbols'.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_symbols": "undefined"},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(iam_passwd.change.after, "require_uppercase_characters")

	obj := {
		"message": sprintf("IAM account password policy %v does not contain 'require_uppercase_characters'.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"require_uppercase_characters": "undefined"},
	}
}

iam_password_policy[obj] {
	iam_passwd := util.iam_account_password_policy_resource_changes[_]
	not utils.is_key_defined(iam_passwd.change.after, "minimum_password_length")

	obj := {
		"message": sprintf("IAM account password policy %v does not contain 'minimum_password_length'.", [iam_passwd.address]),
		"resource": iam_passwd,
		"context": {"minimum_password_length": "undefined"},
	}
}

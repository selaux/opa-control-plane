package global.systemtypes["terraform:2.0"].library.provider.aws.iam.iam_password_policy_aws_foundational_security_best_practices.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.iam.iam_password_policy_aws_foundational_security_best_practices.v1

############
# unit tests

test_iam_account_password_policy_good {
	minimum_password_length := 14
	require_lowercase_characters := true
	require_numbers := true
	require_symbols := true
	require_uppercase_characters := true
	max_password_age := 60
	password_reuse_prevention := 24
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 0
}

test_iam_account_password_policy_one_bad {
	minimum_password_length := 11
	require_lowercase_characters := true
	require_numbers := true
	require_symbols := true
	require_uppercase_characters := true
	max_password_age := 60
	password_reuse_prevention := 24
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 1
}

test_iam_account_password_policy_two_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := true
	require_symbols := true
	require_uppercase_characters := true
	max_password_age := 60
	password_reuse_prevention := 24
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 2
}

test_iam_account_password_policy_three_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := true
	require_uppercase_characters := true
	max_password_age := 60
	password_reuse_prevention := 24
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 3
}

test_iam_account_password_policy_four_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := false
	require_uppercase_characters := true
	max_password_age := 60
	password_reuse_prevention := 24
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 4
}

test_iam_account_password_policy_five_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := false
	require_uppercase_characters := false
	max_password_age := 60
	password_reuse_prevention := 24
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 5
}

test_iam_account_password_policy_six_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := false
	require_uppercase_characters := false
	max_password_age := 91
	password_reuse_prevention := 24
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 6
}

test_iam_account_password_policy_seven_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := false
	require_uppercase_characters := false
	max_password_age := 91
	password_reuse_prevention := 23
	in := input_iam_account_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters, max_password_age, password_reuse_prevention)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 7
}

test_iam_account_password_policy_all_args_absent {
	in := input_iam_account_password_policy_without_arguments
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 7
}

#################
# test input data

input_iam_account_password_policy(a, b, c, d, e, f, g) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.20",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_iam_account_password_policy.strict",
			"mode": "managed",
			"type": "aws_iam_account_password_policy",
			"name": "strict",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"allow_users_to_change_password": true,
				"max_password_age": f,
				"minimum_password_length": a,
				"password_reuse_prevention": g,
				"require_lowercase_characters": b,
				"require_numbers": c,
				"require_symbols": d,
				"require_uppercase_characters": e,
			},
		}]}},
		"resource_changes": [{
			"address": "aws_iam_account_password_policy.strict",
			"mode": "managed",
			"type": "aws_iam_account_password_policy",
			"name": "strict",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"allow_users_to_change_password": true,
					"max_password_age": f,
					"minimum_password_length": a,
					"password_reuse_prevention": g,
					"require_lowercase_characters": b,
					"require_numbers": c,
					"require_symbols": d,
					"require_uppercase_characters": e,
				},
				"after_unknown": {
					"expire_passwords": true,
					"hard_expiry": true,
					"id": true,
				},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {"region": {"constant_value": "us-west-2"}},
			}},
			"root_module": {"resources": [{
				"address": "aws_iam_account_password_policy.strict",
				"mode": "managed",
				"type": "aws_iam_account_password_policy",
				"name": "strict",
				"provider_config_key": "aws",
				"expressions": {
					"allow_users_to_change_password": {"constant_value": true},
					"max_password_age": {"constant_value": 60},
					"minimum_password_length": {"constant_value": 12},
					"password_reuse_prevention": {"constant_value": 24},
					"require_lowercase_characters": {"constant_value": true},
					"require_numbers": {"constant_value": true},
					"require_symbols": {"constant_value": true},
					"require_uppercase_characters": {"constant_value": true},
				},
				"schema_version": 0,
			}]},
		},
	}
}

input_iam_account_password_policy_without_arguments := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.5",
		"variables": {"region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_iam_account_password_policy.no_args",
			"mode": "managed",
			"type": "aws_iam_account_password_policy",
			"name": "no_args",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"allow_users_to_change_password": true,
				"minimum_password_length": 6,
			},
			"sensitive_values": {},
		}]}},
		"resource_changes": [{
			"address": "aws_iam_account_password_policy.no_args",
			"mode": "managed",
			"type": "aws_iam_account_password_policy",
			"name": "no_args",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"allow_users_to_change_password": true,
					"minimum_password_length": 6,
				},
				"after_unknown": {
					"expire_passwords": true,
					"hard_expiry": true,
					"id": true,
					"max_password_age": true,
					"password_reuse_prevention": true,
					"require_lowercase_characters": true,
					"require_numbers": true,
					"require_symbols": true,
					"require_uppercase_characters": true,
				},
				"before_sensitive": false,
				"after_sensitive": {},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 3.27",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"references": ["var.region"]},
				},
			}},
			"root_module": {
				"resources": [{
					"address": "aws_iam_account_password_policy.no_args",
					"mode": "managed",
					"type": "aws_iam_account_password_policy",
					"name": "no_args",
					"provider_config_key": "aws",
					"schema_version": 0,
				}],
				"variables": {"region": {"default": "us-west-2"}},
			},
		},
	}
}

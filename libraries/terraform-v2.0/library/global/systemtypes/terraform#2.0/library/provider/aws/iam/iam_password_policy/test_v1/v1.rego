package global.systemtypes["terraform:2.0"].library.provider.aws.iam.iam_password_policy.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.iam.iam_password_policy.v1

test_iam_password_policy_four_bad {
	minimum_password_length := 12
	require_lowercase_characters := true
	require_numbers := true
	require_symbols := true
	require_uppercase_characters := true
	in := input_iam_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 4
}

test_iam_password_policy_six_bad {
	minimum_password_length := 11
	require_lowercase_characters := true
	require_numbers := true
	require_symbols := true
	require_uppercase_characters := true
	in := input_iam_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 6
}

test_iam_password_policy_seven_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := true
	require_symbols := true
	require_uppercase_characters := true
	in := input_iam_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 7
}

test_iam_password_policy_eight_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := true
	require_uppercase_characters := true
	in := input_iam_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 8
}

test_iam_password_policy_nine_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := false
	require_uppercase_characters := true
	in := input_iam_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 9
}

test_iam_password_policy_ten_bad {
	minimum_password_length := 11
	require_lowercase_characters := false
	require_numbers := false
	require_symbols := false
	require_uppercase_characters := false
	in := input_iam_password_policy(minimum_password_length, require_lowercase_characters, require_numbers, require_symbols, require_uppercase_characters)
	actual := v1.strict_iam_password_policy with input as in
	count(actual) == 10
}

input_iam_password_policy(a, b, c, d, e) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [
				{
					"address": "module.sample_iam.aws_iam_account_password_policy.no_args",
					"mode": "managed",
					"type": "aws_iam_account_password_policy",
					"name": "no_args",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"allow_users_to_change_password": true,
						"minimum_password_length": a,
					},
					"sensitive_values": {},
				},
				{
					"address": "module.sample_iam.aws_iam_account_password_policy.bad",
					"mode": "managed",
					"type": "aws_iam_account_password_policy",
					"name": "bad",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"allow_users_to_change_password": true,
						"max_password_age": 91,
						"minimum_password_length": a,
						"password_reuse_prevention": 23,
						"require_lowercase_characters": b,
						"require_numbers": c,
						"require_symbols": d,
						"require_uppercase_characters": e,
					},
					"sensitive_values": {},
				},
				{
					"address": "module.sample_iam.aws_iam_policy.policy",
					"mode": "managed",
					"type": "aws_iam_policy",
					"name": "policy",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"description": "My test policy",
						"name": "test_policy",
						"name_prefix": null,
						"path": "/",
						"policy": "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
						"tags": null,
					},
					"sensitive_values": {"tags_all": {}},
				},
			],
			"address": "module.sample_iam",
		}]}},
		"resource_changes": [
			{
				"address": "module.sample_iam.aws_iam_account_password_policy.no_args",
				"module_address": "module.sample_iam",
				"mode": "managed",
				"type": "aws_iam_account_password_policy",
				"name": "no_args",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"allow_users_to_change_password": true,
						"minimum_password_length": a,
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
			},
			{
				"address": "module.sample_iam.aws_iam_account_password_policy.bad",
				"module_address": "module.sample_iam",
				"mode": "managed",
				"type": "aws_iam_account_password_policy",
				"name": "bad",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"allow_users_to_change_password": true,
						"max_password_age": 91,
						"minimum_password_length": a,
						"password_reuse_prevention": 23,
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
					"before_sensitive": false,
					"after_sensitive": {},
				},
			},
			{
				"address": "module.sample_iam.aws_iam_policy.policy",
				"module_address": "module.sample_iam",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "policy",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"description": "My test policy",
						"name": "test_policy",
						"name_prefix": null,
						"path": "/",
						"policy": "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
						"tags": null,
					},
					"after_unknown": {
						"arn": true,
						"id": true,
						"policy_id": true,
						"tags_all": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"tags_all": {}},
				},
			},
		],
		"prior_state": {
			"format_version": "1.0",
			"terraform_version": "1.2.7",
			"values": {"root_module": {"child_modules": [{
				"resources": [{
					"address": "module.sample_iam.data.aws_iam_policy_document.policy_document",
					"mode": "data",
					"type": "aws_iam_policy_document",
					"name": "policy_document",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"id": "784443208",
						"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"*\",\n      \"Resource\": \"*\"\n    }\n  ]\n}",
						"override_json": null,
						"override_policy_documents": null,
						"policy_id": null,
						"source_json": null,
						"source_policy_documents": null,
						"statement": [{
							"actions": ["*"],
							"condition": [],
							"effect": "Allow",
							"not_actions": [],
							"not_principals": [],
							"not_resources": [],
							"principals": [],
							"resources": ["*"],
							"sid": "",
						}],
						"version": "2012-10-17",
					},
					"sensitive_values": {"statement": [{
						"actions": [false],
						"condition": [],
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [],
						"resources": [false],
					}]},
				}],
				"address": "module.sample_iam",
			}]}},
		},
		"configuration": {
			"provider_config": {"module.sample_iam:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.sample_iam",
				"expressions": {"region": {"references": ["var.region"]}},
			}},
			"root_module": {"module_calls": {"sample_iam": {
				"source": "../../../../../modules/iam_policy",
				"module": {
					"resources": [
						{
							"address": "aws_iam_account_password_policy.no_args",
							"mode": "managed",
							"type": "aws_iam_account_password_policy",
							"name": "no_args",
							"provider_config_key": "module.sample_iam:aws",
							"schema_version": 0,
						},
						{
							"address": "aws_iam_account_password_policy.bad",
							"mode": "managed",
							"type": "aws_iam_account_password_policy",
							"name": "bad",
							"provider_config_key": "module.sample_iam:aws",
							"expressions": {
								"allow_users_to_change_password": {"constant_value": true},
								"max_password_age": {"constant_value": 91},
								"minimum_password_length": {"constant_value": 11},
								"password_reuse_prevention": {"constant_value": 23},
								"require_lowercase_characters": {"constant_value": false},
								"require_numbers": {"constant_value": false},
								"require_symbols": {"constant_value": false},
								"require_uppercase_characters": {"constant_value": false},
							},
							"schema_version": 0,
						},
						{
							"address": "aws_iam_policy.policy",
							"mode": "managed",
							"type": "aws_iam_policy",
							"name": "policy",
							"provider_config_key": "module.sample_iam:aws",
							"expressions": {
								"description": {"constant_value": "My test policy"},
								"name": {"constant_value": "test_policy"},
								"path": {"constant_value": "/"},
								"policy": {},
							},
							"schema_version": 0,
						},
						{
							"address": "data.aws_iam_policy_document.policy_document",
							"mode": "data",
							"type": "aws_iam_policy_document",
							"name": "policy_document",
							"provider_config_key": "module.sample_iam:aws",
							"expressions": {"statement": [{
								"actions": {"constant_value": ["*"]},
								"effect": {"constant_value": "Allow"},
								"resources": {"constant_value": ["*"]},
							}]},
							"schema_version": 0,
						},
					],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
	}
}

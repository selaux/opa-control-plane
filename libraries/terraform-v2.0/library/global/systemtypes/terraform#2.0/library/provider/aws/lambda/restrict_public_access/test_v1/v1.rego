package global.systemtypes["terraform:2.0"].library.provider.aws.lambda.restrict_public_access.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.lambda.restrict_public_access.v1

test_restrict_public_access_good_source_arn {
	principal := "*"
	source_account := null
	source_arn := "arn:aws:sns:us-east-2:123456789012:sample-arn"
	in := input_lambda_permission_aws_provider_v3(principal, source_account, source_arn)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 0
}

test_restrict_public_access_good_aws_account_id {
	principal := "123456789012"
	source_account := null
	source_arn := null
	in := input_lambda_permission_aws_provider_v3(principal, source_account, source_arn)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 0
}

test_restrict_public_access_good_source_account {
	principal := "*"
	source_account := "123456789012"
	source_arn := null
	in := input_lambda_permission_aws_provider_v3(principal, source_account, source_arn)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 0
}

test_restrict_public_access_bad {
	principal := "*"
	source_account := null
	source_arn := null
	in := input_lambda_permission_aws_provider_v3(principal, source_account, source_arn)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 1
}

test_restrict_public_access_bad_s3 {
	principal := "s3.amazonaws.com"
	source_account := null
	source_arn := null
	in := input_lambda_permission_aws_provider_v3(principal, source_account, source_arn)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 1
}

test_restrict_public_access_bad_ses {
	principal := "ses.amazonaws.com"
	source_account := null
	source_arn := null
	in := input_lambda_permission_aws_provider_v3(principal, source_account, source_arn)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 1
}

test_restrict_public_access_good_principal_org_id {
	principal := "*"
	source_account := null
	source_arn := null
	principal_org_id := "o-1asd3dxg8f4"
	in := input_lambda_permission_aws_provider_v4(principal, source_account, source_arn, principal_org_id)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 0
}

test_restrict_public_access_bad_principal_org_id {
	principal := "*"
	source_account := null
	source_arn := null
	principal_org_id := null
	in := input_lambda_permission_aws_provider_v4(principal, source_account, source_arn, principal_org_id)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 1
}

test_restrict_public_access_bad_principal_org_id {
	principal := "s3.amazonaws.com"
	source_account := null
	source_arn := null
	principal_org_id := null
	in := input_lambda_permission_aws_provider_v4(principal, source_account, source_arn, principal_org_id)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 1
}

test_restrict_public_access_bad_principal_org_id {
	principal := "ses.amazonaws.com"
	source_account := null
	source_arn := null
	principal_org_id := null
	in := input_lambda_permission_aws_provider_v4(principal, source_account, source_arn, principal_org_id)
	actual := v1.prohibit_lambda_function_with_public_access with input as in
	count(actual) == 1
}

input_lambda_permission_aws_provider_v3(value1, value2, value3) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.8",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.sample_lambda_permission.aws_lambda_permission.allow_cloudwatch",
				"mode": "managed",
				"type": "aws_lambda_permission",
				"name": "allow_cloudwatch",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"action": "lambda:InvokeFunction",
					"event_source_token": null,
					"function_name": "my_function",
					"principal": value1,
					"qualifier": null,
					"source_account": value2,
					"source_arn": value3,
					"statement_id": "AllowExecutionFromCloudWatch",
					"statement_id_prefix": null,
				},
				"sensitive_values": {},
			}],
			"address": "module.sample_lambda_permission",
		}]}},
		"resource_changes": [{
			"address": "module.sample_lambda_permission.aws_lambda_permission.allow_cloudwatch",
			"module_address": "module.sample_lambda_permission",
			"mode": "managed",
			"type": "aws_lambda_permission",
			"name": "allow_cloudwatch",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"action": "lambda:InvokeFunction",
					"event_source_token": null,
					"function_name": "my_function",
					"principal": value1,
					"qualifier": null,
					"source_account": value2,
					"source_arn": value3,
					"statement_id": "AllowExecutionFromCloudWatch",
					"statement_id_prefix": null,
				},
				"after_unknown": {"id": true},
				"before_sensitive": false,
				"after_sensitive": {},
			},
		}],
		"configuration": {
			"provider_config": {"module.sample_lambda_permission:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 3.27",
				"module_address": "module.sample_lambda_permission",
				"expressions": {"region": {"references": ["var.region"]}},
			}},
			"root_module": {"module_calls": {"sample_lambda_permission": {
				"source": "../../../../modules/lambda",
				"module": {
					"resources": [{
						"address": "aws_lambda_permission.allow_cloudwatch",
						"mode": "managed",
						"type": "aws_lambda_permission",
						"name": "allow_cloudwatch",
						"provider_config_key": "module.sample_lambda_permission:aws",
						"expressions": {
							"action": {"constant_value": "lambda:InvokeFunction"},
							"function_name": {"constant_value": "my_function"},
							"principal": {"constant_value": "123412341234"},
							"statement_id": {"constant_value": "AllowExecutionFromCloudWatch"},
						},
						"schema_version": 0,
					}],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
	}
}

input_lambda_permission_aws_provider_v4(value1, value2, value3, value4) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.2",
		"variables": {"region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_lambda_permission.lambda_permission",
			"mode": "managed",
			"type": "aws_lambda_permission",
			"name": "lambda_permission",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"action": "lambda:InvokeFunction",
				"event_source_token": null,
				"function_name": "my_function",
				"principal": value1,
				"principal_org_id": value4,
				"qualifier": null,
				"source_account": value2,
				"source_arn": value3,
				"statement_id_prefix": null,
			},
			"sensitive_values": {},
		}]}},
		"resource_changes": [{
			"address": "aws_lambda_permission.lambda_permission",
			"mode": "managed",
			"type": "aws_lambda_permission",
			"name": "lambda_permission",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"action": "lambda:InvokeFunction",
					"event_source_token": null,
					"function_name": "my_function",
					"principal": value1,
					"principal_org_id": value4,
					"qualifier": null,
					"source_account": value2,
					"source_arn": value3,
					"statement_id_prefix": null,
				},
				"after_unknown": {
					"id": true,
					"statement_id": true,
				},
				"before_sensitive": false,
				"after_sensitive": {},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"expressions": {"region": {"references": ["var.region"]}},
			}},
			"root_module": {
				"resources": [{
					"address": "aws_lambda_permission.lambda_permission",
					"mode": "managed",
					"type": "aws_lambda_permission",
					"name": "lambda_permission",
					"provider_config_key": "aws",
					"expressions": {
						"action": {"constant_value": "lambda:InvokeFunction"},
						"function_name": {"constant_value": "my_function"},
						"principal": {"constant_value": "123456789876"},
					},
					"schema_version": 0,
				}],
				"variables": {"region": {"default": "us-west-2"}},
			},
		},
	}
}

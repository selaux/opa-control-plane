package global.systemtypes["terraform:2.0"].library.provider.aws.s3.restrict_asterisk_in_bucket_policy.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.s3.restrict_asterisk_in_bucket_policy.v1

test_restrict_all_actions_in_bucket_policy_good {
	policy_config = "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:ListBucket\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"IpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n"
	in := input_with_bucket_policy(policy_config)

	actual := v1.restrict_all_actions_in_bucket_policy with input as in

	count(actual) == 0
}

test_restrict_all_actions_in_bucket_policy_bad {
	policy_config = "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"IpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n"
	in := input_with_bucket_policy(policy_config)

	actual := v1.restrict_all_actions_in_bucket_policy with input as in

	count(actual) == 1
}

test_tf_bucket_containing_multiple_actions_finds_first_violation {
	in := {
		"format_version": "1.1",
		"terraform_version": "1.2.5",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_s3_bucket.my_public_bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "my_public_bucket",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bucket": "my_public_bucket",
					"bucket_prefix": null,
					"force_destroy": false,
					"tags": null,
					"timeouts": null,
				},
				"sensitive_values": {
					"cors_rule": [],
					"grant": [],
					"lifecycle_rule": [],
					"logging": [],
					"object_lock_configuration": [],
					"replication_configuration": [],
					"server_side_encryption_configuration": [],
					"tags_all": {},
					"versioning": [],
					"website": [],
				},
			},
			{
				"address": "aws_s3_bucket_policy.public_bucket_policy",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "public_bucket_policy",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"testing:*\"\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"s3:*\"\n    }\n  ]\n}"},
				"sensitive_values": {},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.my_public_bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "my_public_bucket",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket": "my_public_bucket",
						"bucket_prefix": null,
						"force_destroy": false,
						"tags": null,
						"timeouts": null,
					},
					"after_unknown": {
						"acceleration_status": true,
						"acl": true,
						"arn": true,
						"bucket_domain_name": true,
						"bucket_regional_domain_name": true,
						"cors_rule": true,
						"grant": true,
						"hosted_zone_id": true,
						"id": true,
						"lifecycle_rule": true,
						"logging": true,
						"object_lock_configuration": true,
						"object_lock_enabled": true,
						"policy": true,
						"region": true,
						"replication_configuration": true,
						"request_payer": true,
						"server_side_encryption_configuration": true,
						"tags_all": true,
						"versioning": true,
						"website": true,
						"website_domain": true,
						"website_endpoint": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"cors_rule": [],
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": [],
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags_all": {},
						"versioning": [],
						"website": [],
					},
				},
			},
			{
				"address": "aws_s3_bucket_policy.public_bucket_policy",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "public_bucket_policy",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"testing:*\"\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"s3:*\"\n    }\n  ]\n}"},
					"after_unknown": {
						"bucket": true,
						"id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {},
				},
			},
		],
		"prior_state": {
			"format_version": "1.0",
			"terraform_version": "1.2.5",
			"values": {"root_module": {"resources": [{
				"address": "data.aws_iam_policy_document.public_bucket_policy",
				"mode": "data",
				"type": "aws_iam_policy_document",
				"name": "public_bucket_policy",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"id": "873064038",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"testing:*\"\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"s3:*\"\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [
						{
							"actions": ["testing:*"],
							"condition": [],
							"effect": "Allow",
							"not_actions": [],
							"not_principals": [],
							"not_resources": [],
							"principals": [],
							"resources": [],
							"sid": "",
						},
						{
							"actions": ["s3:*"],
							"condition": [],
							"effect": "Allow",
							"not_actions": [],
							"not_principals": [],
							"not_resources": [],
							"principals": [],
							"resources": [],
							"sid": "",
						},
					],
					"version": "2012-10-17",
				},
				"sensitive_values": {"statement": [
					{
						"actions": [false],
						"condition": [],
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [],
						"resources": [],
					},
					{
						"actions": [false],
						"condition": [],
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [],
						"resources": [],
					},
				]},
			}]}},
		},
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"expressions": {
					"access_key": {"constant_value": "mock_access_key"},
					"region": {"constant_value": "us-east-1"},
					"secret_key": {"constant_value": "mock_secret_key"},
					"skip_credentials_validation": {"constant_value": true},
					"skip_metadata_api_check": {"constant_value": true},
					"skip_requesting_account_id": {"constant_value": true},
				},
			}},
			"root_module": {"resources": [
				{
					"address": "aws_s3_bucket.my_public_bucket",
					"mode": "managed",
					"type": "aws_s3_bucket",
					"name": "my_public_bucket",
					"provider_config_key": "aws",
					"expressions": {"bucket": {"constant_value": "my_public_bucket"}},
					"schema_version": 0,
				},
				{
					"address": "aws_s3_bucket_policy.public_bucket_policy",
					"mode": "managed",
					"type": "aws_s3_bucket_policy",
					"name": "public_bucket_policy",
					"provider_config_key": "aws",
					"expressions": {
						"bucket": {"references": ["aws_s3_bucket.my_public_bucket.id", "aws_s3_bucket.my_public_bucket"]},
						"policy": {"references": ["data.aws_iam_policy_document.public_bucket_policy.json", "data.aws_iam_policy_document.public_bucket_policy"]},
					},
					"schema_version": 0,
				},
				{
					"address": "data.aws_iam_policy_document.public_bucket_policy",
					"mode": "data",
					"type": "aws_iam_policy_document",
					"name": "public_bucket_policy",
					"provider_config_key": "aws",
					"expressions": {"statement": [
						{"actions": {"constant_value": ["testing:*"]}},
						{"actions": {"constant_value": ["s3:*"]}},
						{"actions": {"constant_value": ["testing:*"]}},
					]},
					"schema_version": 0,
				},
			]},
		},
		"relevant_attributes": [
			{
				"resource": "data.aws_iam_policy_document.public_bucket_policy",
				"attribute": ["json"],
			},
			{
				"resource": "aws_s3_bucket.my_public_bucket",
				"attribute": ["id"],
			},
		],
	}

	actual := v1.restrict_all_actions_in_bucket_policy with input as in

	count(actual) == 2
}

input_with_bucket_policy(policy_config) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.15",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_s3_bucket.b",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "b",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"acl": "private",
					"bucket": "my-tf-test-bucket",
					"bucket_prefix": null,
					"cors_rule": [],
					"force_destroy": false,
					"grant": [],
					"lifecycle_rule": [],
					"logging": [],
					"object_lock_configuration": [],
					"policy": null,
					"replication_configuration": [],
					"server_side_encryption_configuration": [],
					"tags": null,
					"website": [],
				},
			},
			{
				"address": "aws_s3_bucket_policy.b",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "b",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {"policy": policy_config},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.b",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "b",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"acl": "private",
						"bucket": "my-tf-test-bucket",
						"bucket_prefix": null,
						"cors_rule": [],
						"force_destroy": false,
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": [],
						"policy": null,
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags": null,
						"website": [],
					},
					"after_unknown": {
						"acceleration_status": true,
						"arn": true,
						"bucket_domain_name": true,
						"bucket_regional_domain_name": true,
						"cors_rule": [],
						"grant": [],
						"hosted_zone_id": true,
						"id": true,
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": [],
						"region": true,
						"replication_configuration": [],
						"request_payer": true,
						"server_side_encryption_configuration": [],
						"versioning": true,
						"website": [],
						"website_domain": true,
						"website_endpoint": true,
					},
				},
			},
			{
				"address": "aws_s3_bucket_policy.b",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "b",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {"policy": policy_config},
					"after_unknown": {
						"bucket": true,
						"id": true,
					},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"version_constraint": "v2.70.0",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"constant_value": "us-east-1"},
				},
			}},
			"root_module": {"resources": [
				{
					"address": "aws_s3_bucket.b",
					"mode": "managed",
					"type": "aws_s3_bucket",
					"name": "b",
					"provider_config_key": "aws",
					"expressions": {"bucket": {"constant_value": "my-tf-test-bucket"}},
					"schema_version": 0,
				},
				{
					"address": "aws_s3_bucket_policy.b",
					"mode": "managed",
					"type": "aws_s3_bucket_policy",
					"name": "b",
					"provider_config_key": "aws",
					"expressions": {
						"bucket": {"references": ["aws_s3_bucket.b"]},
						"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"IpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n"},
					},
					"schema_version": 0,
				},
			]},
		},
	}
}

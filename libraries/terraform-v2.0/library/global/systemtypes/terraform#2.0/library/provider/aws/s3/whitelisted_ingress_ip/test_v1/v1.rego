package global.systemtypes["terraform:2.0"].library.provider.aws.s3.whitelisted_ingress_ip.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.s3.whitelisted_ingress_ip.v1

test_bucket_policy_with_whitelisted_ips_good {
	in := input_with_bucket_policy
	p := {"allowed_ips": {"8.8.8.8/32", "7.7.7.7/32", "9.9.9.9/31"}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_bucket_policy_with_whitelisted_ips_bad {
	in := input_with_bucket_policy
	p := {"allowed_ips": {"6.6.6.6/32", "7.7.7.7/32", "9.9.9.9/31"}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_bucket_policy_with_whitelisted_ips_good_with_wildcard_param {
	in := input_with_bucket_policy
	p := {"allowed_ips": {"*"}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_bucket_policy_with_whitelisted_ips_bad_no_params {
	in := input_with_bucket_policy
	p := {"allowed_ips": {}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_bucket_with_whitelisted_ips_good {
	in := input_with_bucket
	p := {"allowed_ips": {"8.8.8.8/32", "7.7.7.7/32", "9.9.9.9/31"}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_bucket_with_whitelisted_ips_bad {
	in := input_with_bucket
	p := {"allowed_ips": {"6.6.6.6/32", "7.7.7.7/32", "9.9.9.9/31"}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_bucket_with_whitelisted_ips_good_with_wildcard_param {
	in := input_with_bucket
	p := {"allowed_ips": {"*"}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_bucket_with_whitelisted_ips_bad_no_params {
	in := input_with_bucket
	p := {"allowed_ips": {}}

	actual := v1.bucket_policy_with_whitelisted_ips with input as in
		with data.library.parameters as p

	count(actual) == 1
}

input_with_bucket_policy := {
	"format_version": "0.1",
	"terraform_version": "0.12.15",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.good_bucket",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "good_bucket",
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
			"address": "aws_s3_bucket_policy.good_bucket_policy",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "good_bucket_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"NotIpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n"},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_s3_bucket.good_bucket",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "good_bucket",
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
			"address": "aws_s3_bucket_policy.good_bucket_policy",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "good_bucket_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"NotIpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n"},
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
				"address": "aws_s3_bucket.good_bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "good_bucket",
				"provider_config_key": "aws",
				"expressions": {"bucket": {"constant_value": "my-tf-test-bucket"}},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket_policy.good_bucket_policy",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "good_bucket_policy",
				"provider_config_key": "aws",
				"expressions": {
					"bucket": {"references": ["aws_s3_bucket.good_bucket"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"NotIpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
		]},
	},
}

input_with_bucket := {
	"format_version": "0.1",
	"terraform_version": "0.12.15",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.good_bucket",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "good_bucket",
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
			"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"NotIpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n",
			"replication_configuration": [],
			"server_side_encryption_configuration": [],
			"tags": null,
			"website": [],
		},
	}]}},
	"resource_changes": [{
		"address": "aws_s3_bucket.good_bucket",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "good_bucket",
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
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"NotIpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n",
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
	}],
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
				"address": "aws_s3_bucket.good_bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "good_bucket",
				"provider_config_key": "aws",
				"expressions": {"bucket": {"constant_value": "my-tf-test-bucket"}},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket_policy.good_bucket_policy",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "good_bucket_policy",
				"provider_config_key": "aws",
				"expressions": {
					"bucket": {"references": ["aws_s3_bucket.good_bucket"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"MYBUCKETPOLICY\",\n  \"Statement\": [\n    {\n      \"Sid\": \"IPAllow\",\n      \"Effect\": \"Deny\",\n      \"Principal\": \"*\",\n      \"Action\": \"s3:*\",\n      \"Resource\": \"arn:aws:s3:::my_tf_test_bucket/*\",\n      \"Condition\": {\n         \"NotIpAddress\": {\"aws:SourceIp\": \"8.8.8.8/32\"}\n      }\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
		]},
	},
}

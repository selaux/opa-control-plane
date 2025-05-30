package global.systemtypes["terraform:2.0"].library.provider.aws.s3.unencrypted.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.s3.unencrypted.v1

bucket_resource_changes_after_values := {
	"bucket": "bucket",
	"bucket_prefix": null,
	"force_destroy": false,
	"tags": null,
	"timeouts": null,
}

bucket_reference_good := [
	"aws_s3_bucket.bucket.bucket",
	"aws_s3_bucket.bucket",
]

bucket_reference_bad := [
	"aws_s3_bucket.fake_bucket.bucket",
	"aws_s3_bucket.fake_bucket",
]

test_unencrypted_s3_bucket_good {
	server_side_encryption_configuration := [{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}]
	new_bucket_resource_changes_after_values := json.patch(bucket_resource_changes_after_values, [{"op": "add", "path": "/server_side_encryption_configuration", "value": server_side_encryption_configuration}])
	in = input_s3_bucket(new_bucket_resource_changes_after_values)
	actual := v1.unencrypted_s3_bucket with input as in
	count(actual) == 0
}

test_unencrypted_s3_bucket_bad {
	in = input_s3_bucket(bucket_resource_changes_after_values)
	actual := v1.unencrypted_s3_bucket with input as in
	count(actual) == 1
}

test_unencrypted_s3_bucket_server_side_encryption_configuration_good {
	rule := [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]
	in = input_s3_bucket_server_side_encryption_configuration_resource(rule)
	actual := v1.unencrypted_s3_bucket with input as in
	count(actual) == 0
}

test_unencrypted_s3_bucket_server_side_encryption_configuration_bad {
	rule := []
	in = input_s3_bucket_server_side_encryption_configuration_resource(rule)
	actual := v1.unencrypted_s3_bucket with input as in
	count(actual) == 1
}

test_s3_bucket_reference_in_s3_bucket_server_side_encryption_configuration_by_bucket_reference_good {
	bucket_name := "some_bucket"
	in := input_s3_bucket_with_server_side_encryption_configuration_resource(bucket_name, bucket_reference_good)
	actual := v1.unencrypted_s3_bucket with input as in
	count(actual) == 0
}

test_s3_bucket_reference_in_s3_bucket_server_side_encryption_configuration_by_bucket_name_good {
	bucket_name := "bucket"
	in := input_s3_bucket_with_server_side_encryption_configuration_resource(bucket_name, bucket_reference_bad)
	actual := v1.unencrypted_s3_bucket with input as in
	count(actual) == 0
}

test_s3_bucket_reference_in_s3_bucket_server_side_encryption_configuration_bad {
	bucket_name := "some_bucket"
	in := input_s3_bucket_with_server_side_encryption_configuration_resource(bucket_name, bucket_reference_bad)
	actual := v1.unencrypted_s3_bucket with input as in
	count(actual) == 1
}

input_s3_bucket_server_side_encryption_configuration_resource(config) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_s3_bucket_server_side_encryption_configuration.test_bucket",
			"mode": "managed",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "test_bucket",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"bucket": "test-bucket",
				"rule": config,
			},
		}]}},
		"resource_changes": [{
			"address": "aws_s3_bucket_server_side_encryption_configuration.test_bucket",
			"mode": "managed",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "test_bucket",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"bucket": "test-bucket",
					"rule": config,
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
					"tags": {},
					"versioning": true,
					"website": [],
					"website_domain": true,
					"website_endpoint": true,
				},
			},
		}],
		"configuration": {"root_module": {"resources": [{
			"address": "aws_s3_bucket.test_bucket",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "test_bucket",
			"provider_config_key": "aws",
			"expressions": {
				"acl": {"constant_value": "private"},
				"bucket": {"constant_value": "my-tf-test-bucket"},
				"tags": {"constant_value": {"Environment": "Dev"}},
			},
			"schema_version": 0,
		}]}},
	}
}

input_s3_bucket(bucket_changes) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"variables": {"aws_region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_s3_bucket.bucket",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "bucket",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"bucket": "bucket",
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
		}]}},
		"resource_changes": [{
			"address": "aws_s3_bucket.bucket",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "bucket",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": bucket_changes,
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
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {
				"resources": [{
					"address": "aws_s3_bucket.bucket",
					"mode": "managed",
					"type": "aws_s3_bucket",
					"name": "bucket",
					"provider_config_key": "aws",
					"expressions": {"bucket": {"constant_value": "bucket"}},
					"schema_version": 0,
				}],
				"variables": {"aws_region": {
					"default": "us-west-2",
					"description": "AWS region",
				}},
			},
		},
	}
}

input_s3_bucket_with_server_side_encryption_configuration_resource(bucket_name, bucket_reference) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"variables": {"aws_region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_kms_key.mykey",
				"mode": "managed",
				"type": "aws_kms_key",
				"name": "mykey",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bypass_policy_lockout_safety_check": false,
					"custom_key_store_id": null,
					"customer_master_key_spec": "SYMMETRIC_DEFAULT",
					"deletion_window_in_days": 10,
					"description": "This key is used to encrypt bucket objects",
					"enable_key_rotation": false,
					"is_enabled": true,
					"key_usage": "ENCRYPT_DECRYPT",
					"tags": null,
				},
				"sensitive_values": {"tags_all": {}},
			},
			{
				"address": "aws_s3_bucket.bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "bucket",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bucket": "bucket",
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
				"address": "aws_s3_bucket_server_side_encryption_configuration.constant",
				"mode": "managed",
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"name": "constant",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bucket": "some-other-bucket",
					"expected_bucket_owner": null,
					"rule": [{
						"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}],
						"bucket_key_enabled": null,
					}],
				},
				"sensitive_values": {"rule": [{"apply_server_side_encryption_by_default": [{}]}]},
			},
			{
				"address": "aws_s3_bucket_server_side_encryption_configuration.reference",
				"mode": "managed",
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"name": "reference",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bucket": "bucket",
					"expected_bucket_owner": null,
					"rule": [{
						"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}],
						"bucket_key_enabled": null,
					}],
				},
				"sensitive_values": {"rule": [{"apply_server_side_encryption_by_default": [{}]}]},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_kms_key.mykey",
				"mode": "managed",
				"type": "aws_kms_key",
				"name": "mykey",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bypass_policy_lockout_safety_check": false,
						"custom_key_store_id": null,
						"customer_master_key_spec": "SYMMETRIC_DEFAULT",
						"deletion_window_in_days": 10,
						"description": "This key is used to encrypt bucket objects",
						"enable_key_rotation": false,
						"is_enabled": true,
						"key_usage": "ENCRYPT_DECRYPT",
						"tags": null,
					},
					"after_unknown": {
						"arn": true,
						"id": true,
						"key_id": true,
						"multi_region": true,
						"policy": true,
						"tags_all": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"tags_all": {}},
				},
			},
			{
				"address": "aws_s3_bucket.bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "bucket",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket": "bucket",
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
				"address": "aws_s3_bucket_server_side_encryption_configuration.constant",
				"mode": "managed",
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"name": "constant",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket": "some-other-bucket",
						"expected_bucket_owner": null,
						"rule": [{
							"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}],
							"bucket_key_enabled": null,
						}],
					},
					"after_unknown": {
						"id": true,
						"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}],
					},
					"before_sensitive": false,
					"after_sensitive": {"rule": [{"apply_server_side_encryption_by_default": [{}]}]},
				},
			},
			{
				"address": "aws_s3_bucket_server_side_encryption_configuration.reference",
				"mode": "managed",
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"name": "reference",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket": "bucket",
						"expected_bucket_owner": null,
						"rule": [{
							"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}],
							"bucket_key_enabled": null,
						}],
					},
					"after_unknown": {
						"id": true,
						"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}],
					},
					"before_sensitive": false,
					"after_sensitive": {"rule": [{"apply_server_side_encryption_by_default": [{}]}]},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {
				"resources": [
					{
						"address": "aws_kms_key.mykey",
						"mode": "managed",
						"type": "aws_kms_key",
						"name": "mykey",
						"provider_config_key": "aws",
						"expressions": {
							"deletion_window_in_days": {"constant_value": 10},
							"description": {"constant_value": "This key is used to encrypt bucket objects"},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_s3_bucket.bucket",
						"mode": "managed",
						"type": "aws_s3_bucket",
						"name": "bucket",
						"provider_config_key": "aws",
						"expressions": {"bucket": {"constant_value": "bucket"}},
						"schema_version": 0,
					},
					{
						"address": "aws_s3_bucket_server_side_encryption_configuration.constant",
						"mode": "managed",
						"type": "aws_s3_bucket_server_side_encryption_configuration",
						"name": "constant",
						"provider_config_key": "aws",
						"expressions": {
							"bucket": {"constant_value": bucket_name},
							"rule": [{"apply_server_side_encryption_by_default": [{
								"kms_master_key_id": {"references": [
									"aws_kms_key.mykey.arn",
									"aws_kms_key.mykey",
								]},
								"sse_algorithm": {"constant_value": "aws:kms"},
							}]}],
						},
						"schema_version": 0,
					},
					{
						"address": "aws_s3_bucket_server_side_encryption_configuration.reference",
						"mode": "managed",
						"type": "aws_s3_bucket_server_side_encryption_configuration",
						"name": "reference",
						"provider_config_key": "aws",
						"expressions": {
							"bucket": {"references": bucket_reference},
							"rule": [{"apply_server_side_encryption_by_default": [{
								"kms_master_key_id": {"references": [
									"aws_kms_key.mykey.arn",
									"aws_kms_key.mykey",
								]},
								"sse_algorithm": {"constant_value": "aws:kms"},
							}]}],
						},
						"schema_version": 0,
					},
				],
				"variables": {"aws_region": {
					"default": "us-west-2",
					"description": "AWS region",
				}},
			},
		},
		"relevant_attributes": [
			{
				"resource": "aws_kms_key.mykey",
				"attribute": ["arn"],
			},
			{
				"resource": "aws_s3_bucket.bucket",
				"attribute": ["bucket"],
			},
		],
	}
}

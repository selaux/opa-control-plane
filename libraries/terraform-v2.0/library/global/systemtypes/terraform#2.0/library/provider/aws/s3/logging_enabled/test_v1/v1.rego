package global.systemtypes["terraform:2.0"].library.provider.aws.s3.logging_enabled.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.s3.logging_enabled.v1

bucket_reference_good := [
	"aws_s3_bucket.example.id",
	"aws_s3_bucket.example",
]

bucket_reference_bad := [
	"aws_s3_bucket.fake_example.id",
	"aws_s3_bucket.fake_example",
]

test_logging_configured_inside_bucket_good {
	in := input_s3_bucket_with_logging_configured_inside_resource
	actual := v1.logging_enabled with input as in
	count(actual) == 0
}

test_logging_configured_inside_bucket_bad {
	in := input_s3_bucket_without_logging_configured_inside_resource
	actual := v1.logging_enabled with input as in
	count(actual) == 1
}

test_s3_bucket_reference_in_s3_bucket_logging_by_bucket_reference_good {
	bucket_name := "some-bucket"
	in := input_s3_bucket_with_logging_configured_outside_resource(bucket_name, bucket_reference_good)
	actual := v1.logging_enabled with input as in
	count(actual) == 0
}

test_s3_bucket_reference_in_s3_bucket_logging_by_bucket_name_good {
	bucket_name := "example"
	in := input_s3_bucket_with_logging_configured_outside_resource(bucket_name, bucket_reference_bad)
	actual := v1.logging_enabled with input as in
	count(actual) == 0
}

test_s3_bucket_reference_in_s3_bucket_logging_bad {
	bucket_name := "fake-example"
	in := input_s3_bucket_with_logging_configured_outside_resource(bucket_name, bucket_reference_bad)
	actual := v1.logging_enabled with input as in
	count(actual) == 1
}

input_s3_bucket_with_logging_configured_inside_resource := {
	"format_version": "1.1",
	"terraform_version": "1.2.7",
	"variables": {"aws_region": {"value": "us-west-2"}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.good",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "good",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"schema_version": 0,
		"values": {
			"bucket": "good",
			"bucket_prefix": null,
			"force_destroy": false,
			"logging": [{
				"target_bucket": "bundle-registry-01",
				"target_prefix": "log/good",
			}],
			"tags": null,
			"timeouts": null,
		},
		"sensitive_values": {
			"cors_rule": [],
			"grant": [],
			"lifecycle_rule": [],
			"logging": [{}],
			"object_lock_configuration": [],
			"replication_configuration": [],
			"server_side_encryption_configuration": [],
			"tags_all": {},
			"versioning": [],
			"website": [],
		},
	}]}},
	"resource_changes": [{
		"address": "aws_s3_bucket.good",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "good",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"bucket": "good",
				"bucket_prefix": null,
				"force_destroy": false,
				"logging": [{
					"target_bucket": "bundle-registry-01",
					"target_prefix": "log/good",
				}],
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
				"logging": [{}],
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
				"logging": [{}],
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
				"address": "aws_s3_bucket.good",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "good",
				"provider_config_key": "aws",
				"expressions": {
					"bucket": {"constant_value": "good"},
					"logging": [{
						"target_bucket": {"constant_value": "bundle-registry-01"},
						"target_prefix": {"constant_value": "log/good"},
					}],
				},
				"schema_version": 0,
			}],
			"variables": {"aws_region": {
				"default": "us-west-2",
				"description": "AWS region",
			}},
		},
	},
}

input_s3_bucket_without_logging_configured_inside_resource := {
	"format_version": "1.1",
	"terraform_version": "1.2.7",
	"variables": {"aws_region": {"value": "us-west-2"}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.bad",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "bad",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"schema_version": 0,
		"values": {
			"bucket": "bad",
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
		"address": "aws_s3_bucket.bad",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "bad",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"bucket": "bad",
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
				"address": "aws_s3_bucket.bad",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "bad",
				"provider_config_key": "aws",
				"expressions": {"bucket": {"constant_value": "bad"}},
				"schema_version": 0,
			}],
			"variables": {"aws_region": {
				"default": "us-west-2",
				"description": "AWS region",
			}},
		},
	},
}

input_s3_bucket_with_logging_configured_outside_resource(bucket_name, bucket_reference) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"variables": {"aws_region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_s3_bucket.example",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bucket": "example",
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
				"address": "aws_s3_bucket.log_bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "log_bucket",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bucket": "log-bucket",
					"bucket_prefix": null,
					"force_destroy": false,
					"logging": [{
						"target_bucket": "bundle-registry-01",
						"target_prefix": "log/good",
					}],
					"tags": null,
					"timeouts": null,
				},
				"sensitive_values": {
					"cors_rule": [],
					"grant": [],
					"lifecycle_rule": [],
					"logging": [{}],
					"object_lock_configuration": [],
					"replication_configuration": [],
					"server_side_encryption_configuration": [],
					"tags_all": {},
					"versioning": [],
					"website": [],
				},
			},
			{
				"address": "aws_s3_bucket_logging.reference_by_attribute",
				"mode": "managed",
				"type": "aws_s3_bucket_logging",
				"name": "reference_by_attribute",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"expected_bucket_owner": null,
					"target_grant": [],
					"target_prefix": "log/example",
				},
				"sensitive_values": {"target_grant": []},
			},
			{
				"address": "aws_s3_bucket_logging.reference_by_name",
				"mode": "managed",
				"type": "aws_s3_bucket_logging",
				"name": "reference_by_name",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"bucket": "some-bucket",
					"expected_bucket_owner": null,
					"target_grant": [],
					"target_prefix": "log/some/",
				},
				"sensitive_values": {"target_grant": []},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.example",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket": "example",
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
				"address": "aws_s3_bucket.log_bucket",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "log_bucket",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket": "log-bucket",
						"bucket_prefix": null,
						"force_destroy": false,
						"logging": [{
							"target_bucket": "bundle-registry-01",
							"target_prefix": "log/good",
						}],
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
						"logging": [{}],
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
						"logging": [{}],
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
				"address": "aws_s3_bucket_logging.reference_by_attribute",
				"mode": "managed",
				"type": "aws_s3_bucket_logging",
				"name": "reference_by_attribute",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"expected_bucket_owner": null,
						"target_grant": [],
						"target_prefix": "log/example",
					},
					"after_unknown": {
						"bucket": true,
						"id": true,
						"target_bucket": true,
						"target_grant": [],
					},
					"before_sensitive": false,
					"after_sensitive": {"target_grant": []},
				},
			},
			{
				"address": "aws_s3_bucket_logging.reference_by_name",
				"mode": "managed",
				"type": "aws_s3_bucket_logging",
				"name": "reference_by_name",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket": "some-bucket",
						"expected_bucket_owner": null,
						"target_grant": [],
						"target_prefix": "log/some/",
					},
					"after_unknown": {
						"id": true,
						"target_bucket": true,
						"target_grant": [],
					},
					"before_sensitive": false,
					"after_sensitive": {"target_grant": []},
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
						"address": "aws_s3_bucket.example",
						"mode": "managed",
						"type": "aws_s3_bucket",
						"name": "example",
						"provider_config_key": "aws",
						"expressions": {"bucket": {"constant_value": "example"}},
						"schema_version": 0,
					},
					{
						"address": "aws_s3_bucket.log_bucket",
						"mode": "managed",
						"type": "aws_s3_bucket",
						"name": "log_bucket",
						"provider_config_key": "aws",
						"expressions": {
							"bucket": {"constant_value": "log-bucket"},
							"logging": [{
								"target_bucket": {"constant_value": "bundle-registry-01"},
								"target_prefix": {"constant_value": "log/good"},
							}],
						},
						"schema_version": 0,
					},
					{
						"address": "aws_s3_bucket_logging.reference_by_attribute",
						"mode": "managed",
						"type": "aws_s3_bucket_logging",
						"name": "reference_by_attribute",
						"provider_config_key": "aws",
						"expressions": {
							"bucket": {"references": bucket_reference},
							"target_bucket": {"references": [
								"aws_s3_bucket.log_bucket.id",
								"aws_s3_bucket.log_bucket",
							]},
							"target_prefix": {"constant_value": "log/example"},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_s3_bucket_logging.reference_by_name",
						"mode": "managed",
						"type": "aws_s3_bucket_logging",
						"name": "reference_by_name",
						"provider_config_key": "aws",
						"expressions": {
							"bucket": {"constant_value": bucket_name},
							"target_bucket": {"references": [
								"aws_s3_bucket.log_bucket.id",
								"aws_s3_bucket.log_bucket",
							]},
							"target_prefix": {"constant_value": "log/some/"},
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
				"resource": "aws_s3_bucket.log_bucket",
				"attribute": ["id"],
			},
			{
				"resource": "aws_s3_bucket.example",
				"attribute": ["id"],
			},
		],
	}
}

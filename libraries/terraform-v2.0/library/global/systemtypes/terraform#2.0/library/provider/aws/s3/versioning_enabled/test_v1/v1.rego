package global.systemtypes["terraform:2.0"].library.provider.aws.s3.versioning_enabled.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.s3.versioning_enabled.v1

versioning_reference_good := [
	"aws_s3_bucket.versioning_by_different_resource.id",
	"aws_s3_bucket.versioning_by_different_resource",
]

versioning_reference_bad := [
	"aws_s3_bucket.fake_resource.id",
	"aws_s3_bucket.fake_resource",
]

# Test 1
# Scenario:
# - aws_s3_bucket without versioning block and with an associated aws_s3_bucket_versioning with versioning enabled -> Pass
# - aws_s3_bucket with versioning block defined and enabled = true and without associated aws_s3_bucket_versioning resource -> Pass
# Resources:
# - bucket resource 1          -> versioning not defined, referred in aws_s3_bucket_versioning -> Pass
# - bucket resource 2          -> versioning defined and enabled                               -> Pass
# - bucket_versioning resource -> versioning enabled                                           -> Pass
test_versioning_enabled_bucket_with_good_referred_versioning_and_good_bucket_and_good_versioning_resource {
	bucket_resource_versioning_enabled := true
	versioning_resource_status_enabled := "Enabled"
	in := input_s3_resources(bucket_resource_versioning_enabled, versioning_resource_status_enabled, versioning_reference_good)
	actual := v1.versioning_enabled with input as in
	count(actual) == 0
}

# Test 2
# Scenario:
# - aws_s3_bucket without versioning block (block not present) and without associated aws_s3_bucket_versioning resource -> Fail
# - aws_s3_bucket with versioning block defined and enabled = true and without associated aws_s3_bucket_versioning resource -> Pass
# - aws_s3_bucket_versioning resource with versioning enabled -> Pass
# Resources:
# - bucket resource 1          -> versioning not defined, not referred in aws_s3_bucket_versioning -> Fail
# - bucket resource 2          -> versioning defined and enabled                                   -> Pass
# - bucket_versioning resource -> versioning enabled                                               -> Pass
test_versioning_enabled_bucket_with_bad_referred_versioning_and_good_bucket_and_good_versioning_resource {
	bucket_resource_versioning_enabled := true
	versioning_resource_status_enabled := "Enabled"
	in := input_s3_resources(bucket_resource_versioning_enabled, versioning_resource_status_enabled, versioning_reference_bad)
	actual := v1.versioning_enabled with input as in
	count(actual) == 1
}

# Test 3
# Scenario:
# - aws_s3_bucket without versioning block and with an associated aws_s3_bucket_versioning with versioning disabled -> Fail
# - aws_s3_bucket with versioning block defined and enabled = true and without associated aws_s3_bucket_versioning resource -> Pass
# Resources:
# - bucket resource 1          -> versioning not defined, referred in aws_s3_bucket_versioning -> Pass
# - bucket resource 2          -> versioning defined and enabled                               -> Pass
# - bucket_versioning resource -> versioning disabled                                          -> Fail
test_versioning_enabled_bucket_with_good_referred_versioning_and_good_bucket_bad_versioning_resource {
	bucket_resource_versioning_enabled := true
	versioning_resource_status_enabled := "Disabled"
	in := input_s3_resources(bucket_resource_versioning_enabled, versioning_resource_status_enabled, versioning_reference_good)
	actual := v1.versioning_enabled with input as in
	count(actual) == 1
}

# Test 4
# Scenario:
# - aws_s3_bucket without versioning block and without an associated aws_s3_bucket_versioning with versioning disabled -> Fail
# - aws_s3_bucket with versioning block defined and enabled = true and without associated aws_s3_bucket_versioning resourced -> Pass
# - aws_s3_bucket_versioning resource with versioning disabled -> Fail
# Resources:
# - bucket resource 1          -> versioning not defined, not referred in aws_s3_bucket_versioning -> Fail
# - bucket resource 2          -> versioning defined and enabled                                   -> Pass
# - bucket_versioning resource -> versioning disabled                                              -> Fail
test_versioning_enabled_bucket_with_bad_referred_versioning_and_good_bucket_bad_versioning_resource {
	bucket_resource_versioning_enabled := true
	versioning_resource_status_enabled := "Disabled"
	in := input_s3_resources(bucket_resource_versioning_enabled, versioning_resource_status_enabled, versioning_reference_bad)
	actual := v1.versioning_enabled with input as in
	count(actual) == 2
}

# Test 5
# Scenario:
# - aws_s3_bucket without versioning block and with an associated aws_s3_bucket_versioning with versioning disabled -> Fail
# - aws_s3_bucket with versioning block defined but enabled = false and without associated aws_s3_bucket_versioning resource -> Fail
# Resources:
# - bucket resource 1          -> versioning not defined, referred in aws_s3_bucket_versioning -> Pass
# - bucket resource 2          -> versioning defined and disabled                              -> Fail
# - bucket_versioning resource -> versioning disabled                                          -> Fail
test_versioning_enabled_bucket_with_good_referred_versioning_and_bad_bucket_bad_versioning_resource {
	bucket_resource_versioning_enabled := false
	versioning_resource_status_enabled := "Disabled"
	in := input_s3_resources(bucket_resource_versioning_enabled, versioning_resource_status_enabled, versioning_reference_good)
	actual := v1.versioning_enabled with input as in
	count(actual) == 2
}

# Test 6
# Scenario:
# - aws_s3_bucket without versioning block and without an associated aws_s3_bucket_versioning with versioning enabled -> Fail
# - aws_s3_bucket with versioning block defined but enabled = false and without associated aws_s3_bucket_versioning resource -> Fail
# - aws_s3_bucket_versioning resource with versioning disabled -> Fail
# Resources:
# - bucket resource 1          -> versioning not defined, not referred in aws_s3_bucket_versioning -> Fail
# - bucket resource 2          -> versioning defined and disabled                                  -> Fail
# - bucket_versioning resource -> versioning disabled                                              -> Fail
test_versioning_enabled_bucket_with_bad_referred_versioning_and_bad_bucket_bad_versioning_resource {
	bucket_resource_versioning_enabled := false
	versioning_resource_status_enabled := "Disabled"
	in := input_s3_resources(bucket_resource_versioning_enabled, versioning_resource_status_enabled, versioning_reference_bad)
	actual := v1.versioning_enabled with input as in
	count(actual) == 3
}

input_s3_resources(bucket_status_value, versioning_status_value, versioning_block_references) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [
				{
					"address": "module.s3.aws_s3_bucket.versioning_by_different_resource",
					"mode": "managed",
					"type": "aws_s3_bucket",
					"name": "versioning_by_different_resource",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"acl": "private",
						"bucket": "my-tf-test-bucket-versioning-by-different-resource",
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
					"address": "module.s3.aws_s3_bucket.versioning_defined",
					"mode": "managed",
					"type": "aws_s3_bucket",
					"name": "versioning_defined",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"acl": "private",
						"bucket": "my-tf-test-good-bucket",
						"bucket_prefix": null,
						"force_destroy": false,
						"tags": null,
						"timeouts": null,
						"versioning": [{
							"enabled": bucket_status_value,
							"mfa_delete": false,
						}],
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
						"versioning": [{}],
						"website": [],
					},
				},
				{
					"address": "module.s3.aws_s3_bucket_versioning.example",
					"mode": "managed",
					"type": "aws_s3_bucket_versioning",
					"name": "example",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"expected_bucket_owner": null,
						"mfa": null,
						"versioning_configuration": [{"status": versioning_status_value}],
					},
					"sensitive_values": {"versioning_configuration": [{}]},
				},
			],
			"address": "module.s3",
		}]}},
		"resource_changes": [
			{
				"address": "module.s3.aws_s3_bucket.versioning_by_different_resource",
				"module_address": "module.s3",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "versioning_by_different_resource",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"acl": "private",
						"bucket": "my-tf-test-bucket-versioning-by-different-resource",
						"bucket_prefix": null,
						"force_destroy": false,
						"tags": null,
						"timeouts": null,
					},
					"after_unknown": {
						"acceleration_status": true,
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
				"address": "module.s3.aws_s3_bucket.versioning_defined",
				"module_address": "module.s3",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "versioning_defined",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"acl": "private",
						"bucket": "my-tf-test-good-bucket",
						"bucket_prefix": null,
						"force_destroy": false,
						"tags": null,
						"timeouts": null,
						"versioning": [{
							"enabled": bucket_status_value,
							"mfa_delete": false,
						}],
					},
					"after_unknown": {
						"acceleration_status": true,
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
						"versioning": [{}],
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
						"versioning": [{}],
						"website": [],
					},
				},
			},
			{
				"address": "module.s3.aws_s3_bucket_versioning.example",
				"module_address": "module.s3",
				"mode": "managed",
				"type": "aws_s3_bucket_versioning",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"expected_bucket_owner": null,
						"mfa": null,
						"versioning_configuration": [{"status": versioning_status_value}],
					},
					"after_unknown": {
						"bucket": true,
						"id": true,
						"versioning_configuration": [{"mfa_delete": true}],
					},
					"before_sensitive": false,
					"after_sensitive": {"versioning_configuration": [{}]},
				},
			},
		],
		"configuration": {
			"provider_config": {"module.s3:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.s3",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {"module_calls": {"s3": {
				"source": "../../../../../modules/s3",
				"module": {
					"resources": [
						{
							"address": "aws_s3_bucket.versioning_by_different_resource",
							"mode": "managed",
							"type": "aws_s3_bucket",
							"name": "versioning_by_different_resource",
							"provider_config_key": "module.s3:aws",
							"expressions": {
								"acl": {"constant_value": "private"},
								"bucket": {"constant_value": "my-tf-test-bucket-versioning-by-different-resource"},
							},
							"schema_version": 0,
						},
						{
							"address": "aws_s3_bucket.versioning_defined",
							"mode": "managed",
							"type": "aws_s3_bucket",
							"name": "versioning_defined",
							"provider_config_key": "module.s3:aws",
							"expressions": {
								"acl": {"constant_value": "private"},
								"bucket": {"constant_value": "my-tf-test-good-bucket"},
								"versioning": [{"enabled": {"constant_value": true}}],
							},
							"schema_version": 0,
						},
						{
							"address": "aws_s3_bucket_versioning.example",
							"mode": "managed",
							"type": "aws_s3_bucket_versioning",
							"name": "example",
							"provider_config_key": "module.s3:aws",
							"expressions": {
								"bucket": {"references": versioning_block_references},
								"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
							},
							"schema_version": 0,
						},
					],
					"variables": {"aws_region": {
						"default": "us-west-2",
						"description": "AWS region",
					}},
				},
			}}},
		},
		"relevant_attributes": [{
			"resource": "module.s3.aws_s3_bucket.versioning_by_different_resource",
			"attribute": ["id"],
		}],
	}
}

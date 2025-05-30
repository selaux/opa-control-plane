package global.systemtypes["terraform:2.0"].library.provider.aws.cloudtrail.server_side_encryption.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.cloudtrail.server_side_encryption.v1

test_server_side_encryption_good {
	in := input_cloudtrail_with_kms_key_id_config
	actual := v1.prohibit_trails_without_server_side_encryption with input as in

	count(actual) == 0
}

test_server_side_encryption_bad {
	in := input_cloudtrail_without_kms_key_id_config
	actual := v1.prohibit_trails_without_server_side_encryption with input as in

	count(actual) == 1
}

input_cloudtrail_with_kms_key_id_config = {
	"format_version": "1.1",
	"terraform_version": "1.2.5",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_cloudtrail.cloudtrail_sample",
		"mode": "managed",
		"type": "aws_cloudtrail",
		"name": "cloudtrail_sample",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"schema_version": 0,
		"values": {
			"advanced_event_selector": [],
			"cloud_watch_logs_group_arn": null,
			"cloud_watch_logs_role_arn": null,
			"enable_log_file_validation": false,
			"enable_logging": true,
			"event_selector": [],
			"include_global_service_events": false,
			"insight_selector": [],
			"is_multi_region_trail": false,
			"is_organization_trail": false,
			"kms_key_id": "arn:aws:kms:us-west-2:546653085803:alias/cloudtrail",
			"name": "tf-trail-sample",
			"s3_key_prefix": "prefix",
			"sns_topic_name": null,
			"tags": null,
		},
	}]}},
	"resource_changes": [{
		"address": "aws_cloudtrail.cloudtrail_sample",
		"mode": "managed",
		"type": "aws_cloudtrail",
		"name": "cloudtrail_sample",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"advanced_event_selector": [],
				"cloud_watch_logs_group_arn": null,
				"cloud_watch_logs_role_arn": null,
				"enable_log_file_validation": false,
				"enable_logging": true,
				"event_selector": [],
				"include_global_service_events": false,
				"insight_selector": [],
				"is_multi_region_trail": false,
				"is_organization_trail": false,
				"kms_key_id": "arn:aws:kms:us-west-2:546653085803:alias/cloudtrail",
				"name": "tf-trail-sample",
				"s3_key_prefix": "prefix",
				"sns_topic_name": null,
				"tags": null,
			},
		},
	}],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_cloudtrail.cloudtrail_sample",
		"mode": "managed",
		"type": "aws_cloudtrail",
		"name": "cloudtrail_sample",
		"provider_config_key": "aws",
		"expressions": {
			"include_global_service_events": {"constant_value": false},
			"kms_key_id": {"references": [
				"data.aws_kms_key.by_alias_arn.key_id",
				"data.aws_kms_key.by_alias_arn",
			]},
			"name": {"constant_value": "tf-trail-sample"},
			"s3_bucket_name": {"references": [
				"aws_s3_bucket.bucket1.id",
				"aws_s3_bucket.bucket1",
			]},
			"s3_key_prefix": {"constant_value": "prefix"},
		},
		"schema_version": 0,
		"depends_on": [
			"aws_s3_bucket_policy.CloudTrailS3Bucket",
			"aws_s3_bucket.bucket1",
		],
	}]}},
}

input_cloudtrail_without_kms_key_id_config = {
	"format_version": "1.1",
	"terraform_version": "1.2.5",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_cloudtrail.cloudtrail_sample",
		"mode": "managed",
		"type": "aws_cloudtrail",
		"name": "cloudtrail_sample",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"schema_version": 0,
		"values": {
			"advanced_event_selector": [],
			"cloud_watch_logs_group_arn": null,
			"cloud_watch_logs_role_arn": null,
			"enable_log_file_validation": false,
			"enable_logging": true,
			"event_selector": [],
			"include_global_service_events": false,
			"insight_selector": [],
			"is_multi_region_trail": false,
			"is_organization_trail": false,
			"name": "tf-trail-sample",
			"s3_key_prefix": "prefix",
			"sns_topic_name": null,
			"tags": null,
		},
	}]}},
	"resource_changes": [{
		"address": "aws_cloudtrail.cloudtrail_sample",
		"mode": "managed",
		"type": "aws_cloudtrail",
		"name": "cloudtrail_sample",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"advanced_event_selector": [],
				"cloud_watch_logs_group_arn": null,
				"cloud_watch_logs_role_arn": null,
				"enable_log_file_validation": false,
				"enable_logging": true,
				"event_selector": [],
				"include_global_service_events": false,
				"insight_selector": [],
				"is_multi_region_trail": false,
				"is_organization_trail": false,
				"name": "tf-trail-sample",
				"s3_key_prefix": "prefix",
				"sns_topic_name": null,
				"tags": null,
			},
		},
	}],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_cloudtrail.cloudtrail_sample",
		"mode": "managed",
		"type": "aws_cloudtrail",
		"name": "cloudtrail_sample",
		"provider_config_key": "aws",
		"expressions": {
			"include_global_service_events": {"constant_value": false},
			"name": {"constant_value": "tf-trail-sample"},
			"s3_bucket_name": {"references": [
				"aws_s3_bucket.bucket1.id",
				"aws_s3_bucket.bucket1",
			]},
			"s3_key_prefix": {"constant_value": "prefix"},
		},
		"schema_version": 0,
		"depends_on": [
			"aws_s3_bucket_policy.CloudTrailS3Bucket",
			"aws_s3_bucket.bucket1",
		],
	}]}},
}

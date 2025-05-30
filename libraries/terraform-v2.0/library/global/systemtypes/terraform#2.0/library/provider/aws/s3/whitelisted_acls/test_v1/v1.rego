package global.systemtypes["terraform:2.0"].library.provider.aws.s3.whitelisted_acls.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.s3.whitelisted_acls.v1
import data.library.parameters

test_s3_whitelisted_acls_in_bucket_good {
	in = input_s3_bucket("private")
	p := {"allowed_acls": {"private", "authenticated-read"}}

	actual := v1.whitelist_s3_acls with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_s3_whitelisted_acls_in_bucket_bad {
	in = input_s3_bucket("public-read")
	p := {"allowed_acls": {"private", "authenticated-read"}}

	actual := v1.whitelist_s3_acls with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_s3_whitelisted_acls_in_bucket_acls_good {
	in = input_s3_bucket_acl("private")
	p := {"allowed_acls": {"private", "authenticated-read"}}

	actual := v1.whitelist_s3_acls with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_s3_whitelisted_acls_in_bucket_acls_bad {
	in = input_s3_bucket_acl("public-read")
	p := {"allowed_acls": {"private", "authenticated-read"}}

	actual := v1.whitelist_s3_acls with input as in
		with data.library.parameters as p

	count(actual) == 1
}

input_s3_bucket(acl) := {
	"format_version": "0.1",
	"terraform_version": "0.12.20",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.b",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "b",
		"provider_name": "aws",
		"schema_version": 0,
		"values": {
			"acl": acl,
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
			"tags": {
				"Environment": "Dev",
				"Name": "My bucket",
			},
			"website": [],
		},
	}]}},
	"resource_changes": [{
		"address": "aws_s3_bucket.b",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"name": "b",
		"provider_name": "aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"acl": acl,
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
				"tags": {
					"Environment": "Dev",
					"Name": "My bucket",
				},
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
				"tags": {},
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
			"expressions": {"region": {"constant_value": "us-east-1"}},
		}},
		"root_module": {"resources": [{
			"address": "aws_s3_bucket.b",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "b",
			"provider_config_key": "aws",
			"expressions": {
				"acl": {"constant_value": "private"},
				"bucket": {"constant_value": "my-tf-test-bucket"},
				"tags": {"constant_value": {
					"Environment": "Dev",
					"Name": "My bucket",
				}},
			},
			"schema_version": 0,
		}]},
	},
}

input_s3_bucket_acl(acl) := {
	"format_version": "0.1",
	"terraform_version": "0.12.20",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_acl.b",
		"mode": "managed",
		"type": "aws_s3_bucket_acl",
		"name": "b",
		"provider_name": "aws",
		"schema_version": 0,
		"values": {
			"acl": acl,
			"bucket": "my-tf-test-bucket",
		},
	}]}},
	"resource_changes": [{
		"address": "aws_s3_bucket_acl.b",
		"mode": "managed",
		"type": "aws_s3_bucket_acl",
		"name": "b",
		"provider_name": "aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"acl": acl,
				"bucket": "my-tf-test-bucket",
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
	"configuration": {
		"provider_config": {"aws": {
			"name": "aws",
			"expressions": {"region": {"constant_value": "us-east-1"}},
		}},
		"root_module": {"resources": [{
			"address": "aws_s3_bucket.b",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "b",
			"provider_config_key": "aws",
			"expressions": {
				"acl": {"constant_value": "private"},
				"bucket": {"constant_value": "my-tf-test-bucket"},
				"tags": {"constant_value": {
					"Environment": "Dev",
					"Name": "My bucket",
				}},
			},
			"schema_version": 0,
		}]},
	},
}

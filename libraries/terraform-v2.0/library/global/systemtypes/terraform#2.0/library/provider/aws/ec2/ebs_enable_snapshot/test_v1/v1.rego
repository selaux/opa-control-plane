package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.ebs_enable_snapshot.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ec2.ebs_enable_snapshot.v1

input_value = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_ebs_snapshot.example_snapshot",
				"mode": "managed",
				"type": "aws_ebs_snapshot",
				"name": "example_snapshot",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"description": null,
					"tags": {"Name": "HelloWorld_snap"},
					"timeouts": null,
				},
			},
			{
				"address": "aws_ebs_volume.bad_example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "bad_example",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-east-1a",
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
			},
			{
				"address": "aws_ebs_volume.example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "example",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-east-1a",
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_ebs_snapshot.example_snapshot",
				"mode": "managed",
				"type": "aws_ebs_snapshot",
				"name": "example_snapshot",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"description": null,
						"tags": {"Name": "HelloWorld_snap"},
						"timeouts": null,
					},
					"after_unknown": {
						"arn": true,
						"data_encryption_key_id": true,
						"encrypted": true,
						"id": true,
						"kms_key_id": true,
						"owner_alias": true,
						"owner_id": true,
						"tags": {},
						"volume_id": true,
						"volume_size": true,
					},
				},
			},
			{
				"address": "aws_ebs_volume.bad_example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "bad_example",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"availability_zone": "us-east-1a",
						"multi_attach_enabled": null,
						"outpost_arn": null,
						"size": 40,
						"tags": {"Name": "HelloWorld"},
					},
					"after_unknown": {
						"arn": true,
						"encrypted": true,
						"id": true,
						"iops": true,
						"kms_key_id": true,
						"snapshot_id": true,
						"tags": {},
						"throughput": true,
						"type": true,
					},
				},
			},
			{
				"address": "aws_ebs_volume.example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "example",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"availability_zone": "us-east-1a",
						"multi_attach_enabled": null,
						"outpost_arn": null,
						"size": 40,
						"tags": {"Name": "HelloWorld"},
					},
					"after_unknown": {
						"arn": true,
						"encrypted": true,
						"id": true,
						"iops": true,
						"kms_key_id": true,
						"snapshot_id": true,
						"tags": {},
						"throughput": true,
						"type": true,
					},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [
				{
					"address": "aws_ebs_snapshot.example_snapshot",
					"mode": "managed",
					"type": "aws_ebs_snapshot",
					"name": "example_snapshot",
					"provider_config_key": "aws",
					"expressions": {
						"tags": {"constant_value": {"Name": "HelloWorld_snap"}},
						"volume_id": {"references": ["aws_ebs_volume.example"]},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_ebs_volume.bad_example",
					"mode": "managed",
					"type": "aws_ebs_volume",
					"name": "bad_example",
					"provider_config_key": "aws",
					"expressions": {
						"availability_zone": {"constant_value": "us-east-1a"},
						"size": {"constant_value": 40},
						"tags": {"constant_value": {"Name": "HelloWorld"}},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_ebs_volume.example",
					"mode": "managed",
					"type": "aws_ebs_volume",
					"name": "example",
					"provider_config_key": "aws",
					"expressions": {
						"availability_zone": {"constant_value": "us-east-1a"},
						"size": {"constant_value": 40},
						"tags": {"constant_value": {"Name": "HelloWorld"}},
					},
					"schema_version": 0,
				},
			]},
		},
	}
}

input_value_with_no_ebs_snapshot = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_ebs_volume.bad_example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "bad_example",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-east-1a",
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
			},
			{
				"address": "aws_ebs_volume.example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "example",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-east-1a",
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_ebs_volume.bad_example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "bad_example",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"availability_zone": "us-east-1a",
						"multi_attach_enabled": null,
						"outpost_arn": null,
						"size": 40,
						"tags": {"Name": "HelloWorld"},
					},
					"after_unknown": {
						"arn": true,
						"encrypted": true,
						"id": true,
						"iops": true,
						"kms_key_id": true,
						"snapshot_id": true,
						"tags": {},
						"throughput": true,
						"type": true,
					},
				},
			},
			{
				"address": "aws_ebs_volume.example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "example",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"availability_zone": "us-east-1a",
						"multi_attach_enabled": null,
						"outpost_arn": null,
						"size": 40,
						"tags": {"Name": "HelloWorld"},
					},
					"after_unknown": {
						"arn": true,
						"encrypted": true,
						"id": true,
						"iops": true,
						"kms_key_id": true,
						"snapshot_id": true,
						"tags": {},
						"throughput": true,
						"type": true,
					},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [
				{
					"address": "aws_ebs_volume.bad_example",
					"mode": "managed",
					"type": "aws_ebs_volume",
					"name": "bad_example",
					"provider_config_key": "aws",
					"expressions": {
						"availability_zone": {"constant_value": "us-east-1a"},
						"size": {"constant_value": 40},
						"tags": {"constant_value": {"Name": "HelloWorld"}},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_ebs_volume.example",
					"mode": "managed",
					"type": "aws_ebs_volume",
					"name": "example",
					"provider_config_key": "aws",
					"expressions": {
						"availability_zone": {"constant_value": "us-east-1a"},
						"size": {"constant_value": 40},
						"tags": {"constant_value": {"Name": "HelloWorld"}},
					},
					"schema_version": 0,
				},
			]},
		},
	}
}

input_value_with_no_ebs_volume_reference = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_ebs_snapshot.example_snapshot",
				"mode": "managed",
				"type": "aws_ebs_snapshot",
				"name": "example_snapshot",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"description": null,
					"tags": {"Name": "HelloWorld_snap"},
					"timeouts": null,
				},
			},
			{
				"address": "aws_ebs_volume.bad_example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "bad_example",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-east-1a",
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
			},
			{
				"address": "aws_ebs_volume.example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "example",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-east-1a",
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_ebs_snapshot.example_snapshot",
				"mode": "managed",
				"type": "aws_ebs_snapshot",
				"name": "example_snapshot",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"description": null,
						"tags": {"Name": "HelloWorld_snap"},
						"timeouts": null,
					},
					"after_unknown": {
						"arn": true,
						"data_encryption_key_id": true,
						"encrypted": true,
						"id": true,
						"kms_key_id": true,
						"owner_alias": true,
						"owner_id": true,
						"tags": {},
						"volume_id": true,
						"volume_size": true,
					},
				},
			},
			{
				"address": "aws_ebs_volume.bad_example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "bad_example",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"availability_zone": "us-east-1a",
						"multi_attach_enabled": null,
						"outpost_arn": null,
						"size": 40,
						"tags": {"Name": "HelloWorld"},
					},
					"after_unknown": {
						"arn": true,
						"encrypted": true,
						"id": true,
						"iops": true,
						"kms_key_id": true,
						"snapshot_id": true,
						"tags": {},
						"throughput": true,
						"type": true,
					},
				},
			},
			{
				"address": "aws_ebs_volume.example",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "example",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"availability_zone": "us-east-1a",
						"multi_attach_enabled": null,
						"outpost_arn": null,
						"size": 40,
						"tags": {"Name": "HelloWorld"},
					},
					"after_unknown": {
						"arn": true,
						"encrypted": true,
						"id": true,
						"iops": true,
						"kms_key_id": true,
						"snapshot_id": true,
						"tags": {},
						"throughput": true,
						"type": true,
					},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [
				{
					"address": "aws_ebs_snapshot.example_snapshot",
					"mode": "managed",
					"type": "aws_ebs_snapshot",
					"name": "example_snapshot",
					"provider_config_key": "aws",
					"expressions": {
						"tags": {"constant_value": {"Name": "HelloWorld_snap"}},
						"volume_id": {"references": ["aws_ebs_volume.fake_example"]},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_ebs_volume.bad_example",
					"mode": "managed",
					"type": "aws_ebs_volume",
					"name": "bad_example",
					"provider_config_key": "aws",
					"expressions": {
						"availability_zone": {"constant_value": "us-east-1a"},
						"size": {"constant_value": 40},
						"tags": {"constant_value": {"Name": "HelloWorld"}},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_ebs_volume.example",
					"mode": "managed",
					"type": "aws_ebs_volume",
					"name": "example",
					"provider_config_key": "aws",
					"expressions": {
						"availability_zone": {"constant_value": "us-east-1a"},
						"size": {"constant_value": 40},
						"tags": {"constant_value": {"Name": "HelloWorld"}},
					},
					"schema_version": 0,
				},
			]},
		},
	}
}

test_ebs_volume_has_ebs_snapshot_good {
	in := input_value
	actual := v1.ec2_ebs_enable_snapshot with input as in
	count(actual) == 1
}

test_ebs_volume_not_having_ebs_snapshot_bad {
	in := input_value_with_no_ebs_snapshot
	actual := v1.ec2_ebs_enable_snapshot with input as in
	count(actual) == 2
}

test_ebs_volume_not_referenced_in_ebs_snapshot_bad {
	in := input_value_with_no_ebs_volume_reference
	actual := v1.ec2_ebs_enable_snapshot with input as in
	count(actual) == 2
}

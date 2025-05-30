package global.systemtypes["terraform:2.0"].library.provider.aws.dms.publicly_accessible.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.dms.publicly_accessible.v1

test_publicly_accessible_dms_good {
	accessible := false
	in := input_dms_replication_instance(accessible)
	actual := v1.prohibit_publicly_accessible_dms_replication_instance with input as in
	count(actual) == 0
}

test_publicly_accessible_dms_bad {
	accessible := true
	in := input_dms_replication_instance(accessible)
	actual := v1.prohibit_publicly_accessible_dms_replication_instance with input as in
	count(actual) == 1
}

input_dms_replication_instance(value) = x {
	x := {
		"format_version": "1.0",
		"terraform_version": "1.1.9",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.sample_dms.aws_dms_replication_instance.tf_dms",
				"mode": "managed",
				"type": "aws_dms_replication_instance",
				"name": "tf_dms",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"allocated_storage": 20,
					"allow_major_version_upgrade": null,
					"apply_immediately": true,
					"auto_minor_version_upgrade": true,
					"availability_zone": "us-west-2c",
					"engine_version": "3.4.6",
					"kms_key_arn": "arn:aws:kms:us-west-2:546653085803:key/9a1d5407-5450-4449-be1a-531348fd9aca",
					"multi_az": false,
					"preferred_maintenance_window": "sun:10:30-sun:14:30",
					"publicly_accessible": value,
					"replication_instance_class": "dms.t3.medium",
					"replication_instance_id": "test-dms-replication-instance-tf",
					"tags": {"Name": "MyInstance"},
					"tags_all": {"Name": "MyInstance"},
					"timeouts": null,
				},
				"sensitive_values": {
					"replication_instance_private_ips": [],
					"replication_instance_public_ips": [],
					"tags": {},
					"tags_all": {},
					"vpc_security_group_ids": [],
				},
			}],
			"address": "module.sample_dms",
		}]}},
		"resource_changes": [{
			"address": "module.sample_dms.aws_dms_replication_instance.tf_dms",
			"module_address": "module.sample_dms",
			"mode": "managed",
			"type": "aws_dms_replication_instance",
			"name": "tf_dms",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"allocated_storage": 20,
					"allow_major_version_upgrade": null,
					"apply_immediately": true,
					"auto_minor_version_upgrade": true,
					"availability_zone": "us-west-2c",
					"engine_version": "3.4.6",
					"kms_key_arn": "arn:aws:kms:us-west-2:546653085803:key/9a1d5407-5450-4449-be1a-531348fd9aca",
					"multi_az": false,
					"preferred_maintenance_window": "sun:10:30-sun:14:30",
					"publicly_accessible": value,
					"replication_instance_class": "dms.t3.medium",
					"replication_instance_id": "test-dms-replication-instance-tf",
					"tags": {"Name": "MyInstance"},
					"tags_all": {"Name": "MyInstance"},
					"timeouts": null,
				},
				"after_unknown": {
					"id": true,
					"replication_instance_arn": true,
					"replication_instance_private_ips": true,
					"replication_instance_public_ips": true,
					"replication_subnet_group_id": true,
					"tags": {},
					"tags_all": {},
					"vpc_security_group_ids": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"replication_instance_private_ips": [],
					"replication_instance_public_ips": [],
					"tags": {},
					"tags_all": {},
					"vpc_security_group_ids": [],
				},
			},
		}],
		"configuration": {
			"provider_config": {"module.sample_dms:aws": {
				"name": "aws",
				"version_constraint": "~> 3.27",
				"module_address": "module.sample_dms",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"references": ["var.region"]},
				},
			}},
			"root_module": {"module_calls": {"sample_dms": {
				"source": "../../../../modules/dms",
				"module": {
					"resources": [{
						"address": "aws_dms_replication_instance.tf_dms",
						"mode": "managed",
						"type": "aws_dms_replication_instance",
						"name": "tf_dms",
						"provider_config_key": "sample_dms:aws",
						"expressions": {
							"allocated_storage": {"constant_value": 20},
							"apply_immediately": {"constant_value": true},
							"auto_minor_version_upgrade": {"constant_value": true},
							"availability_zone": {"constant_value": "us-west-2c"},
							"engine_version": {"constant_value": "3.4.6"},
							"kms_key_arn": {"constant_value": "arn:aws:kms:us-west-2:546653085803:key/9a1d5407-5450-4449-be1a-531348fd9aca"},
							"multi_az": {"constant_value": false},
							"preferred_maintenance_window": {"constant_value": "sun:10:30-sun:14:30"},
							"publicly_accessible": {"constant_value": true},
							"replication_instance_class": {"constant_value": "dms.t3.medium"},
							"replication_instance_id": {"constant_value": "test-dms-replication-instance-tf"},
							"replication_subnet_group_id": {"references": [
								"aws_dms_replication_subnet_group.dms_subnet_group.id",
								"aws_dms_replication_subnet_group.dms_subnet_group",
							]},
							"tags": {"constant_value": {"Name": "MyInstance"}},
						},
						"schema_version": 0,
						"depends_on": [
							"aws_iam_role_policy_attachment.dms-access-for-endpoint-AmazonDMSRedshiftS3Role",
							"aws_iam_role_policy_attachment.dms-cloudwatch-logs-role-AmazonDMSCloudWatchLogsRole",
							"aws_iam_role_policy_attachment.dms-vpc-role-AmazonDMSVPCManagementRole",
						],
					}],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
	}
}

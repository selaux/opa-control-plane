package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.ebs_not_encrypted.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ec2.ebs_not_encrypted.v1

test_ec2_ebs_not_encrypted_good {
	in := input_ebs_instance(true)
	actual := v1.ebs_not_encrypted with input as in
	count(actual) == 0
}

test_ec2_ebs_not_encrypted_bad {
	in := input_ebs_instance(false)
	actual := v1.ebs_not_encrypted with input as in
	count(actual) == 1
}

test_ec2_ebs_not_encrypted_bad_1 {
	in := input_ebs_instance_missing_encrypted
	actual := v1.ebs_not_encrypted with input as in
	count(actual) == 1
}

input_ebs_instance(value) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.ebs.aws_ebs_volume.good_resource",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "good_resource",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-west-2c",
					"encrypted": value,
					"final_snapshot": false,
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "good_resource"},
					"tags_all": {"Name": "good_resource"},
					"timeouts": null,
				},
				"sensitive_values": {
					"tags": {},
					"tags_all": {},
				},
			}],
			"address": "module.ebs",
		}]}},
		"resource_changes": [{
			"address": "module.ebs.aws_ebs_volume.good_resource",
			"module_address": "module.ebs",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "good_resource",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"availability_zone": "us-west-2c",
					"encrypted": value,
					"final_snapshot": false,
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "good_resource"},
					"tags_all": {"Name": "good_resource"},
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"iops": true,
					"kms_key_id": true,
					"snapshot_id": true,
					"tags": {},
					"tags_all": {},
					"throughput": true,
					"type": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"tags": {},
					"tags_all": {},
				},
			},
		}],
		"configuration": {
			"provider_config": {"module.ebs:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.ebs",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {"module_calls": {"ebs": {
				"source": "../../../../../modules/ebs",
				"module": {
					"resources": [{
						"address": "aws_ebs_volume.good_resource",
						"mode": "managed",
						"type": "aws_ebs_volume",
						"name": "good_resource",
						"provider_config_key": "module.ebs:aws",
						"expressions": {
							"availability_zone": {"constant_value": "us-west-2c"},
							"encrypted": {"constant_value": true},
							"size": {"constant_value": 40},
							"tags": {"constant_value": {"Name": "good_resource"}},
						},
						"schema_version": 0,
					}],
					"variables": {
						"asg_name": {
							"default": "tf-asg-styra",
							"description": "Name of the autoscaling group",
						},
						"aws_region": {
							"default": "us-west-2",
							"description": "AWS region",
						},
						"instance_type": {
							"default": "m6a.large",
							"description": "Type of the instance for launch configuration",
						},
						"launch_conf_name": {
							"default": "tf-launchconf-styra",
							"description": "Name of the launch configuration",
						},
					},
				},
			}}},
		},
	}
}

input_ebs_instance_missing_encrypted = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.ebs.aws_ebs_volume.bad_resource",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "bad_resource",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"availability_zone": "us-west-2c",
					"final_snapshot": false,
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "bad_resource"},
					"tags_all": {"Name": "bad_resource"},
					"timeouts": null,
				},
				"sensitive_values": {
					"tags": {},
					"tags_all": {},
				},
			}],
			"address": "module.ebs",
		}]}},
		"resource_changes": [{
			"address": "module.ebs.aws_ebs_volume.bad_resource",
			"module_address": "module.ebs",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "bad_resource",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"availability_zone": "us-west-2c",
					"final_snapshot": false,
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "bad_resource"},
					"tags_all": {"Name": "bad_resource"},
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"encrypted": true,
					"id": true,
					"iops": true,
					"kms_key_id": true,
					"snapshot_id": true,
					"tags": {},
					"tags_all": {},
					"throughput": true,
					"type": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"tags": {},
					"tags_all": {},
				},
			},
		}],
		"configuration": {
			"provider_config": {"module.ebs:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.ebs",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {"module_calls": {"ebs": {
				"source": "../../../../../modules/ebs",
				"module": {
					"resources": [{
						"address": "aws_ebs_volume.bad_resource",
						"mode": "managed",
						"type": "aws_ebs_volume",
						"name": "bad_resource",
						"provider_config_key": "module.ebs:aws",
						"expressions": {
							"availability_zone": {"constant_value": "us-west-2c"},
							"size": {"constant_value": 40},
							"tags": {"constant_value": {"Name": "bad_resource"}},
						},
						"schema_version": 0,
					}],
					"variables": {
						"asg_name": {
							"default": "tf-asg-styra",
							"description": "Name of the autoscaling group",
						},
						"aws_region": {
							"default": "us-west-2",
							"description": "AWS region",
						},
						"instance_type": {
							"default": "m6a.large",
							"description": "Type of the instance for launch configuration",
						},
						"launch_conf_name": {
							"default": "tf-launchconf-styra",
							"description": "Name of the launch configuration",
						},
					},
				},
			}}},
		},
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.without_vpc.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ec2.without_vpc.v1

test_ec2_outside_vpc_good {
	value := {
		"ami": "ami-830c94e3",
		"credit_specification": [],
		"disable_api_termination": null,
		"ebs_optimized": null,
		"get_password_data": false,
		"hibernation": null,
		"iam_instance_profile": null,
		"instance_initiated_shutdown_behavior": null,
		"instance_type": "t2.micro",
		"monitoring": null,
		"source_dest_check": true,
		"tags": {"Name": "ExampleInstance"},
		"timeouts": null,
		"user_data": null,
		"user_data_base64": null,
		"volume_tags": null,
		"vpc_security_group_ids": ["sg-0eab2d05"],
	}

	in := input_ec2_instance(value)
	actual := v1.ec2_outside_vpc with input as in
	count(actual) == 0
}

test_ec2_outside_vpc_bad {
	value := {
		"ami": "ami-830c94e3",
		"credit_specification": [],
		"disable_api_termination": null,
		"ebs_optimized": null,
		"get_password_data": false,
		"hibernation": null,
		"iam_instance_profile": null,
		"instance_initiated_shutdown_behavior": null,
		"instance_type": "t2.micro",
		"monitoring": null,
		"source_dest_check": true,
		"tags": {"Name": "ExampleInstance"},
		"timeouts": null,
		"user_data": null,
		"user_data_base64": null,
		"volume_tags": null,
	}

	in := input_ec2_instance(value)
	actual := v1.ec2_outside_vpc with input as in
	count(actual) == 1
}

input_ec2_instance(values) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.20",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_instance.example",
			"mode": "managed",
			"type": "aws_instance",
			"name": "example",
			"provider_name": "aws",
			"schema_version": 1,
			"values": values,
		}]}},
		"resource_changes": [{
			"address": "aws_instance.example",
			"mode": "managed",
			"type": "aws_instance",
			"name": "example",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": values,
				"after_unknown": {
					"arn": true,
					"associate_public_ip_address": true,
					"availability_zone": true,
					"cpu_core_count": true,
					"cpu_threads_per_core": true,
					"credit_specification": [],
					"ebs_block_device": true,
					"enclave_options": true,
					"ephemeral_block_device": true,
					"host_id": true,
					"id": true,
					"instance_state": true,
					"ipv6_address_count": true,
					"ipv6_addresses": true,
					"key_name": true,
					"metadata_options": true,
					"network_interface": true,
					"outpost_arn": true,
					"password_data": true,
					"placement_group": true,
					"primary_network_interface_id": true,
					"private_dns": true,
					"private_ip": true,
					"public_dns": true,
					"public_ip": true,
					"root_block_device": true,
					"secondary_private_ips": true,
					"security_groups": true,
					"subnet_id": true,
					"tags": {},
					"tenancy": true,
					"vpc_security_group_ids": true,
				},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"constant_value": "us-east-1"},
				},
			}},
			"root_module": {"resources": [{
				"address": "aws_instance.example",
				"mode": "managed",
				"type": "aws_instance",
				"name": "example",
				"provider_config_key": "aws",
				"expressions": {
					"ami": {"constant_value": "ami-830c94e3"},
					"instance_type": {"constant_value": "t2.micro"},
					"tags": {"constant_value": {"Name": "ExampleInstance"}},
				},
				"schema_version": 1,
			}]},
		},
	}
}

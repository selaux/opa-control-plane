package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.instance_volume_deletion.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ec2.instance_volume_deletion.v1

input_ebs_block_device(delete_on_termination) := x {
	x := [{
		"delete_on_termination": delete_on_termination,
		"device_name": "/dev/sdg",
		"tags": null,
		"volume_size": 5,
		"volume_type": "gp2",
	}]
}

input_root_block_device(delete_on_termination) := x {
	x := [{
		"delete_on_termination": delete_on_termination,
		"tags": null,
		"volume_size": 5,
		"volume_type": "gp2",
	}]
}

test_instances_volume_deletion_good {
	ebs_value := input_ebs_block_device(false)
	root_value := input_root_block_device(false)
	in := input_instance_volume_deletion(ebs_value, root_value)
	actual := v1.volume_deletion with input as in
	count(actual) == 0
}

test_instances_volume_deletion_ebs_block_true_bad {
	ebs_value := input_ebs_block_device(true)
	root_value := input_root_block_device(false)
	in := input_instance_volume_deletion(ebs_value, root_value)
	actual := v1.volume_deletion with input as in
	count(actual) == 1
}

test_instances_volume_deletion_root_block_true_bad {
	ebs_value := input_ebs_block_device(false)
	root_value := input_root_block_device(true)
	in := input_instance_volume_deletion(ebs_value, root_value)
	actual := v1.volume_deletion with input as in
	count(actual) == 1
}

test_instances_volume_deletion_both_true_bad {
	ebs_value := input_ebs_block_device(true)
	root_value := input_root_block_device(true)
	in := input_instance_volume_deletion(ebs_value, root_value)
	actual := v1.volume_deletion with input as in
	count(actual) == 2
}

test_instances_delete_on_termination_absent_bad {
	ebs_value := [{
		"device_name": "/dev/sdg",
		"tags": null,
		"volume_size": 5,
		"volume_type": "gp2",
	}]
	root_value := [{
		"tags": null,
		"volume_size": 5,
		"volume_type": "gp2",
	}]
	in := input_instance_volume_deletion(ebs_value, root_value)
	actual := v1.volume_deletion with input as in
	count(actual) == 2
}

input_instance_volume_deletion(ebs_block_device, root_block_device) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.ec2.aws_instance.instance_volume_deletion",
				"mode": "managed",
				"type": "aws_instance",
				"name": "instance_volume_deletion",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 1,
				"values": {
					"ami": "ami-12345",
					"credit_specification": [],
					"ebs_block_device": ebs_block_device,
					"get_password_data": false,
					"hibernation": null,
					"instance_type": "t3.micro",
					"launch_template": [],
					"root_block_device": root_block_device,
					"source_dest_check": true,
					"tags": {"Name": "HelloWorld"},
					"tags_all": {"Name": "HelloWorld"},
					"timeouts": null,
					"user_data_replace_on_change": false,
					"volume_tags": null,
				},
				"sensitive_values": {
					"capacity_reservation_specification": [],
					"credit_specification": [],
					"ebs_block_device": [{}],
					"enclave_options": [],
					"ephemeral_block_device": [],
					"ipv6_addresses": [],
					"launch_template": [],
					"maintenance_options": [],
					"metadata_options": [],
					"network_interface": [],
					"private_dns_name_options": [],
					"root_block_device": [{}],
					"secondary_private_ips": [],
					"security_groups": [],
					"tags": {},
					"tags_all": {},
					"vpc_security_group_ids": [],
				},
			}],
			"address": "module.ec2",
		}]}},
		"resource_changes": [{
			"address": "module.ec2.aws_instance.instance_volume_deletion",
			"module_address": "module.ec2",
			"mode": "managed",
			"type": "aws_instance",
			"name": "instance_volume_deletion",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"ami": "ami-12345",
					"credit_specification": [],
					"ebs_block_device": ebs_block_device,
					"get_password_data": false,
					"hibernation": null,
					"instance_type": "t3.micro",
					"launch_template": [],
					"root_block_device": root_block_device,
					"source_dest_check": true,
					"tags": {"Name": "HelloWorld"},
					"tags_all": {"Name": "HelloWorld"},
					"timeouts": null,
					"user_data_replace_on_change": false,
					"volume_tags": null,
				},
				"after_unknown": {
					"arn": true,
					"associate_public_ip_address": true,
					"availability_zone": true,
					"capacity_reservation_specification": true,
					"cpu_core_count": true,
					"cpu_threads_per_core": true,
					"credit_specification": [],
					"disable_api_stop": true,
					"disable_api_termination": true,
					"ebs_block_device": [{
						"encrypted": true,
						"iops": true,
						"kms_key_id": true,
						"snapshot_id": true,
						"throughput": true,
						"volume_id": true,
					}],
					"ebs_optimized": true,
					"enclave_options": true,
					"ephemeral_block_device": true,
					"host_id": true,
					"host_resource_group_arn": true,
					"iam_instance_profile": true,
					"id": true,
					"instance_initiated_shutdown_behavior": true,
					"instance_state": true,
					"ipv6_address_count": true,
					"ipv6_addresses": true,
					"key_name": true,
					"launch_template": [],
					"maintenance_options": true,
					"metadata_options": true,
					"monitoring": true,
					"network_interface": true,
					"outpost_arn": true,
					"password_data": true,
					"placement_group": true,
					"placement_partition_number": true,
					"primary_network_interface_id": true,
					"private_dns": true,
					"private_dns_name_options": true,
					"private_ip": true,
					"public_dns": true,
					"public_ip": true,
					"root_block_device": [{
						"device_name": true,
						"encrypted": true,
						"iops": true,
						"kms_key_id": true,
						"throughput": true,
						"volume_id": true,
					}],
					"secondary_private_ips": true,
					"security_groups": true,
					"subnet_id": true,
					"tags": {},
					"tags_all": {},
					"tenancy": true,
					"user_data": true,
					"user_data_base64": true,
					"vpc_security_group_ids": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"capacity_reservation_specification": [],
					"credit_specification": [],
					"ebs_block_device": [{}],
					"enclave_options": [],
					"ephemeral_block_device": [],
					"ipv6_addresses": [],
					"launch_template": [],
					"maintenance_options": [],
					"metadata_options": [],
					"network_interface": [],
					"private_dns_name_options": [],
					"root_block_device": [{}],
					"secondary_private_ips": [],
					"security_groups": [],
					"tags": {},
					"tags_all": {},
					"vpc_security_group_ids": [],
				},
			},
		}],
		"configuration": {
			"provider_config": {"module.ec2:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.ec2",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {"module_calls": {"ec2": {
				"source": "../../../../../modules/ec2",
				"module": {
					"resources": [{
						"address": "aws_instance.instance_volume_deletion",
						"mode": "managed",
						"type": "aws_instance",
						"name": "instance_volume_deletion",
						"provider_config_key": "module.ec2:aws",
						"expressions": {
							"ami": {"constant_value": "ami-12345"},
							"ebs_block_device": [{
								"delete_on_termination": {"constant_value": false},
								"device_name": {"constant_value": "/dev/sdg"},
								"volume_size": {"constant_value": 5},
								"volume_type": {"constant_value": "gp2"},
							}],
							"instance_type": {"constant_value": "t3.micro"},
							"root_block_device": [{
								"delete_on_termination": {"constant_value": false},
								"volume_size": {"constant_value": 5},
								"volume_type": {"constant_value": "gp2"},
							}],
							"tags": {"constant_value": {"Name": "HelloWorld"}},
						},
						"schema_version": 1,
					}],
					"variables": {"aws_region": {
						"default": "us-west-2",
						"description": "AWS region",
					}},
				},
			}}},
		},
	}
}

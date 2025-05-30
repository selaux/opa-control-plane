package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.whitelist_region.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ec2.whitelist_region.v1
import data.library.parameters

# Scenario:
# - provider aws      - region value constant  -> good
# - provider aws.usw2 - region value reference -> good
# Resources:
# - aws_instance.root_instance                                        - provider aws      - region value constant  -> Pass
# - module.example.aws_instance.level_1_child_instance                - provider aws.usw2 - region value reference -> Pass
# - module.example.module.example.aws_instance.level_2_child_instance - provider aws.usw2 - region value reference -> Pass
test_constant_region_good_and_reference_region_good {
	in := input_scenario_with_multi_level_instances("us-east-1", "us-east-2")
	p := {"allowed_regions": {"us-east-1", "us-east-2", "us-west-1"}}

	actual := v1.ec2_whitelist_region with input as in
		with data.library.parameters as p

	count(actual) == 0
}

# Scenario:
# - provider aws      - region value constant  -> bad
# - provider aws.usw2 - region value reference -> good
# Resources:
# - aws_instance.root_instance                                        - provider aws      - region value constant  -> Fail
# - module.example.aws_instance.level_1_child_instance                - provider aws.usw2 - region value reference -> Pass
# - module.example.module.example.aws_instance.level_2_child_instance - provider aws.usw2 - region value reference -> Pass
test_constant_region_bad_and_reference_region_good {
	in := input_scenario_with_multi_level_instances("us-west-2", "us-east-2")
	p := {"allowed_regions": {"us-east-1", "us-east-2", "us-west-1"}}

	actual := v1.ec2_whitelist_region with input as in
		with data.library.parameters as p

	count(actual) == 1
}

# Scenario:
# - provider aws      - region value constant  -> good
# - provider aws.usw2 - region value reference -> bad
# Resources:
# - aws_instance.root_instance                                        - provider aws      - region value constant  -> Pass
# - module.example.aws_instance.level_1_child_instance                - provider aws.usw2 - region value reference -> Fail
# - module.example.module.example.aws_instance.level_2_child_instance - provider aws.usw2 - region value reference -> Fail
test_constant_region_good_and_reference_region_bad {
	in := input_scenario_with_multi_level_instances("us-east-1", "us-west-2")
	p := {"allowed_regions": {"us-east-1", "us-east-2", "us-west-1"}}

	actual := v1.ec2_whitelist_region with input as in
		with data.library.parameters as p

	count(actual) == 2
}

# Scenario:
# - provider aws      - region value constant  -> bad
# - provider aws.usw2 - region value reference -> bad
# Resources:
# - aws_instance.root_instance                                        - provider aws      - region value constant  -> Fail
# - module.example.aws_instance.level_1_child_instance                - provider aws.usw2 - region value reference -> Fail
# - module.example.module.example.aws_instance.level_2_child_instance - provider aws.usw2 - region value reference -> Fail
test_constant_region_bad_and_reference_region_bad {
	in := input_scenario_with_multi_level_instances("ap-southeast-1", "us-west-2")
	p := {"allowed_regions": {"us-east-1", "us-east-2", "us-west-1"}}

	actual := v1.ec2_whitelist_region with input as in
		with data.library.parameters as p

	count(actual) == 3
}

input_scenario_with_multi_level_instances(planned_region_1, planned_region_2) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"variables": {"aws_region": {"value": planned_region_2}},
		"planned_values": {"root_module": {
			"resources": [{
				"address": "aws_instance.root_instance",
				"mode": "managed",
				"type": "aws_instance",
				"name": "root_instance",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 1,
				"values": {
					"ami": "ami-0747bdcabd34c712a",
					"credit_specification": [],
					"get_password_data": false,
					"hibernation": null,
					"instance_type": "t2.micro",
					"launch_template": [],
					"source_dest_check": true,
					"tags": {"Name": "unapproved_region"},
					"tags_all": {"Name": "unapproved_region"},
					"timeouts": null,
					"user_data_replace_on_change": false,
					"volume_tags": null,
				},
				"sensitive_values": {
					"capacity_reservation_specification": [],
					"credit_specification": [],
					"ebs_block_device": [],
					"enclave_options": [],
					"ephemeral_block_device": [],
					"ipv6_addresses": [],
					"launch_template": [],
					"maintenance_options": [],
					"metadata_options": [],
					"network_interface": [],
					"private_dns_name_options": [],
					"root_block_device": [],
					"secondary_private_ips": [],
					"security_groups": [],
					"tags": {},
					"tags_all": {},
					"vpc_security_group_ids": [],
				},
			}],
			"child_modules": [{
				"resources": [{
					"address": "module.example.aws_instance.level_1_child_instance",
					"mode": "managed",
					"type": "aws_instance",
					"name": "level_1_child_instance",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 1,
					"values": {
						"ami": "ami-0747bdcabd34c712a",
						"credit_specification": [],
						"get_password_data": false,
						"hibernation": null,
						"instance_type": "t2.micro",
						"launch_template": [],
						"source_dest_check": true,
						"tags": {"Name": "unapproved_region"},
						"tags_all": {"Name": "unapproved_region"},
						"timeouts": null,
						"user_data_replace_on_change": false,
						"volume_tags": null,
					},
					"sensitive_values": {
						"capacity_reservation_specification": [],
						"credit_specification": [],
						"ebs_block_device": [],
						"enclave_options": [],
						"ephemeral_block_device": [],
						"ipv6_addresses": [],
						"launch_template": [],
						"maintenance_options": [],
						"metadata_options": [],
						"network_interface": [],
						"private_dns_name_options": [],
						"root_block_device": [],
						"secondary_private_ips": [],
						"security_groups": [],
						"tags": {},
						"tags_all": {},
						"vpc_security_group_ids": [],
					},
				}],
				"address": "module.example",
				"child_modules": [{
					"resources": [{
						"address": "module.example.module.example.aws_instance.level_2_child_instance",
						"mode": "managed",
						"type": "aws_instance",
						"name": "level_2_child_instance",
						"provider_name": "registry.terraform.io/hashicorp/aws",
						"schema_version": 1,
						"values": {
							"ami": "ami-0747bdcabd34c712a",
							"credit_specification": [],
							"get_password_data": false,
							"hibernation": null,
							"instance_type": "t2.micro",
							"launch_template": [],
							"source_dest_check": true,
							"tags": {"Name": "unapproved_region"},
							"tags_all": {"Name": "unapproved_region"},
							"timeouts": null,
							"user_data_replace_on_change": false,
							"volume_tags": null,
						},
						"sensitive_values": {
							"capacity_reservation_specification": [],
							"credit_specification": [],
							"ebs_block_device": [],
							"enclave_options": [],
							"ephemeral_block_device": [],
							"ipv6_addresses": [],
							"launch_template": [],
							"maintenance_options": [],
							"metadata_options": [],
							"network_interface": [],
							"private_dns_name_options": [],
							"root_block_device": [],
							"secondary_private_ips": [],
							"security_groups": [],
							"tags": {},
							"tags_all": {},
							"vpc_security_group_ids": [],
						},
					}],
					"address": "module.example.module.example",
				}],
			}],
		}},
		"resource_changes": [
			{
				"address": "aws_instance.root_instance",
				"mode": "managed",
				"type": "aws_instance",
				"name": "root_instance",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"ami": "ami-0747bdcabd34c712a",
						"credit_specification": [],
						"get_password_data": false,
						"hibernation": null,
						"instance_type": "t2.micro",
						"launch_template": [],
						"source_dest_check": true,
						"tags": {"Name": "unapproved_region"},
						"tags_all": {"Name": "unapproved_region"},
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
						"ebs_block_device": true,
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
						"root_block_device": true,
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
						"ebs_block_device": [],
						"enclave_options": [],
						"ephemeral_block_device": [],
						"ipv6_addresses": [],
						"launch_template": [],
						"maintenance_options": [],
						"metadata_options": [],
						"network_interface": [],
						"private_dns_name_options": [],
						"root_block_device": [],
						"secondary_private_ips": [],
						"security_groups": [],
						"tags": {},
						"tags_all": {},
						"vpc_security_group_ids": [],
					},
				},
			},
			{
				"address": "module.example.aws_instance.level_1_child_instance",
				"module_address": "module.example",
				"mode": "managed",
				"type": "aws_instance",
				"name": "level_1_child_instance",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"ami": "ami-0747bdcabd34c712a",
						"credit_specification": [],
						"get_password_data": false,
						"hibernation": null,
						"instance_type": "t2.micro",
						"launch_template": [],
						"source_dest_check": true,
						"tags": {"Name": "unapproved_region"},
						"tags_all": {"Name": "unapproved_region"},
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
						"ebs_block_device": true,
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
						"root_block_device": true,
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
						"ebs_block_device": [],
						"enclave_options": [],
						"ephemeral_block_device": [],
						"ipv6_addresses": [],
						"launch_template": [],
						"maintenance_options": [],
						"metadata_options": [],
						"network_interface": [],
						"private_dns_name_options": [],
						"root_block_device": [],
						"secondary_private_ips": [],
						"security_groups": [],
						"tags": {},
						"tags_all": {},
						"vpc_security_group_ids": [],
					},
				},
			},
			{
				"address": "module.example.module.example.aws_instance.level_2_child_instance",
				"module_address": "module.example.module.example",
				"mode": "managed",
				"type": "aws_instance",
				"name": "level_2_child_instance",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"ami": "ami-0747bdcabd34c712a",
						"credit_specification": [],
						"get_password_data": false,
						"hibernation": null,
						"instance_type": "t2.micro",
						"launch_template": [],
						"source_dest_check": true,
						"tags": {"Name": "unapproved_region"},
						"tags_all": {"Name": "unapproved_region"},
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
						"ebs_block_device": true,
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
						"root_block_device": true,
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
						"ebs_block_device": [],
						"enclave_options": [],
						"ephemeral_block_device": [],
						"ipv6_addresses": [],
						"launch_template": [],
						"maintenance_options": [],
						"metadata_options": [],
						"network_interface": [],
						"private_dns_name_options": [],
						"root_block_device": [],
						"secondary_private_ips": [],
						"security_groups": [],
						"tags": {},
						"tags_all": {},
						"vpc_security_group_ids": [],
					},
				},
			},
		],
		"configuration": {
			"provider_config": {
				"aws": {
					"name": "aws",
					"full_name": "registry.terraform.io/hashicorp/aws",
					"expressions": {"region": {"constant_value": planned_region_1}},
				},
				"aws.usw2": {
					"name": "aws",
					"full_name": "registry.terraform.io/hashicorp/aws",
					"alias": "usw2",
					"expressions": {"region": {"references": ["var.aws_region"]}},
				},
			},
			"root_module": {
				"resources": [{
					"address": "aws_instance.root_instance",
					"mode": "managed",
					"type": "aws_instance",
					"name": "root_instance",
					"provider_config_key": "aws",
					"expressions": {
						"ami": {"constant_value": "ami-0747bdcabd34c712a"},
						"instance_type": {"constant_value": "t2.micro"},
						"tags": {"constant_value": {"Name": "unapproved_region"}},
					},
					"schema_version": 1,
				}],
				"module_calls": {"example": {
					"source": "./example",
					"module": {
						"resources": [{
							"address": "aws_instance.level_1_child_instance",
							"mode": "managed",
							"type": "aws_instance",
							"name": "level_1_child_instance",
							"provider_config_key": "aws.usw2",
							"expressions": {
								"ami": {"constant_value": "ami-0747bdcabd34c712a"},
								"instance_type": {"constant_value": "t2.micro"},
								"tags": {"constant_value": {"Name": "unapproved_region"}},
							},
							"schema_version": 1,
						}],
						"module_calls": {"example": {
							"source": "./example2",
							"module": {"resources": [{
								"address": "aws_instance.level_2_child_instance",
								"mode": "managed",
								"type": "aws_instance",
								"name": "level_2_child_instance",
								"provider_config_key": "aws.usw2",
								"expressions": {
									"ami": {"constant_value": "ami-0747bdcabd34c712a"},
									"instance_type": {"constant_value": "t2.micro"},
									"tags": {"constant_value": {"Name": "unapproved_region"}},
								},
								"schema_version": 1,
							}]},
						}},
					},
				}},
				"variables": {"aws_region": {"default": planned_region_2}},
			},
		},
	}
}

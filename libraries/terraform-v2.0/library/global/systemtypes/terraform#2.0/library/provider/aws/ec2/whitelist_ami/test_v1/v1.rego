package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.whitelist_ami.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ec2.whitelist_ami.v1
import data.library.parameters

input_value_ec2_instance(ami) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_instance.good_resource_1",
			"mode": "managed",
			"type": "aws_instance",
			"name": "good_resource_1",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"ami": ami,
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
				"tags": {"Name": "good_resource_1"},
				"timeouts": null,
				"user_data": null,
				"user_data_base64": null,
				"volume_tags": null,
			},
		}]}},
		"resource_changes": [{
			"address": "aws_instance.good_resource_1",
			"mode": "managed",
			"type": "aws_instance",
			"name": "good_resource_1",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"ami": ami,
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
					"tags": {"Name": "good_resource_1"},
					"timeouts": null,
					"user_data": null,
					"user_data_base64": null,
					"volume_tags": null,
				},
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
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [
				{
					"address": "aws_instance.bad_resource_1",
					"mode": "managed",
					"type": "aws_instance",
					"name": "bad_resource_1",
					"provider_config_key": "aws",
					"expressions": {
						"ami": {"references": ["local.denied_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
						"tags": {"constant_value": {"Name": "bad_resource_1"}},
					},
					"schema_version": 1,
				},
				{
					"address": "aws_instance.good_resource_1",
					"mode": "managed",
					"type": "aws_instance",
					"name": "good_resource_1",
					"provider_config_key": "aws",
					"expressions": {
						"ami": {"references": ["local.allowed_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
						"tags": {"constant_value": {"Name": "good_resource_1"}},
					},
					"schema_version": 1,
				},
			]},
		},
	}
}

input_value_ec2_lauch_template_config(ami) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.8",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_launch_configuration.configuration_1",
				"mode": "managed",
				"type": "aws_launch_configuration",
				"name": "configuration_1",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"enable_monitoring": true,
					"ephemeral_block_device": [],
					"iam_instance_profile": null,
					"image_id": ami,
					"instance_type": "t2.micro",
					"placement_tenancy": null,
					"security_groups": null,
					"spot_price": null,
					"user_data": null,
					"user_data_base64": null,
					"vpc_classic_link_id": null,
					"vpc_classic_link_security_groups": null,
				},
				"sensitive_values": {
					"ebs_block_device": [],
					"ephemeral_block_device": [],
					"metadata_options": [],
					"root_block_device": [],
				},
			},
			{
				"address": "aws_launch_template.template_1",
				"mode": "managed",
				"type": "aws_launch_template",
				"name": "template_1",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"block_device_mappings": [],
					"capacity_reservation_specification": [],
					"cpu_options": [],
					"credit_specification": [],
					"description": null,
					"disable_api_stop": null,
					"disable_api_termination": null,
					"ebs_optimized": null,
					"elastic_gpu_specifications": [],
					"elastic_inference_accelerator": [],
					"enclave_options": [],
					"hibernation_options": [],
					"iam_instance_profile": [],
					"image_id": "ami-0022c769",
					"instance_initiated_shutdown_behavior": null,
					"instance_market_options": [],
					"instance_requirements": [],
					"instance_type": "t2.micro",
					"kernel_id": null,
					"key_name": null,
					"license_specification": [],
					"maintenance_options": [],
					"monitoring": [],
					"network_interfaces": [],
					"placement": [],
					"private_dns_name_options": [],
					"ram_disk_id": null,
					"security_group_names": null,
					"tag_specifications": [],
					"tags": null,
					"update_default_version": null,
					"user_data": null,
					"vpc_security_group_ids": null,
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_launch_configuration.configuration_1",
				"mode": "managed",
				"type": "aws_launch_configuration",
				"name": "configuration_1",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"enable_monitoring": true,
						"ephemeral_block_device": [],
						"iam_instance_profile": null,
						"image_id": ami,
						"instance_type": "t2.micro",
						"placement_tenancy": null,
						"security_groups": null,
						"spot_price": null,
						"user_data": null,
						"user_data_base64": null,
						"vpc_classic_link_id": null,
						"vpc_classic_link_security_groups": null,
					},
				},
			},
			{
				"address": "aws_launch_template.template_1",
				"mode": "managed",
				"type": "aws_launch_template",
				"name": "template_1",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"block_device_mappings": [],
						"capacity_reservation_specification": [],
						"cpu_options": [],
						"credit_specification": [],
						"description": null,
						"disable_api_stop": null,
						"disable_api_termination": null,
						"ebs_optimized": null,
						"elastic_gpu_specifications": [],
						"elastic_inference_accelerator": [],
						"enclave_options": [],
						"hibernation_options": [],
						"iam_instance_profile": [],
						"image_id": ami,
						"instance_initiated_shutdown_behavior": null,
						"instance_market_options": [],
						"instance_requirements": [],
						"instance_type": "t2.micro",
						"kernel_id": null,
						"key_name": null,
						"license_specification": [],
						"maintenance_options": [],
						"monitoring": [],
						"network_interfaces": [],
						"placement": [],
						"private_dns_name_options": [],
						"ram_disk_id": null,
						"security_group_names": null,
						"tag_specifications": [],
						"tags": null,
						"update_default_version": null,
						"user_data": null,
						"vpc_security_group_ids": null,
					},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"expressions": {"region": {"constant_value": "us-west-2"}},
			}},
			"root_module": {"resources": [
				{
					"address": "aws_instance.bad_instance_1",
					"mode": "managed",
					"type": "aws_instance",
					"name": "bad_instance_1",
					"provider_config_key": "aws",
					"expressions": {
						"ami": {"references": ["local.denied_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
					},
					"schema_version": 1,
				},
				{
					"address": "aws_instance.good_instance_1",
					"mode": "managed",
					"type": "aws_instance",
					"name": "good_instance_1",
					"provider_config_key": "aws",
					"expressions": {
						"ami": {"references": ["local.allowed_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
					},
					"schema_version": 1,
				},
				{
					"address": "aws_launch_configuration.bad_configuration_1",
					"mode": "managed",
					"type": "aws_launch_configuration",
					"name": "bad_configuration_1",
					"provider_config_key": "aws",
					"expressions": {
						"image_id": {"references": ["local.denied_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_launch_configuration.good_configuration_1",
					"mode": "managed",
					"type": "aws_launch_configuration",
					"name": "good_configuration_1",
					"provider_config_key": "aws",
					"expressions": {
						"image_id": {"references": ["local.allowed_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_launch_template.bad_template_1",
					"mode": "managed",
					"type": "aws_launch_template",
					"name": "bad_template_1",
					"provider_config_key": "aws",
					"expressions": {
						"image_id": {"references": ["local.denied_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_launch_template.good_template_1",
					"mode": "managed",
					"type": "aws_launch_template",
					"name": "good_template_1",
					"provider_config_key": "aws",
					"expressions": {
						"image_id": {"references": ["local.allowed_ami"]},
						"instance_type": {"constant_value": "t2.micro"},
					},
					"schema_version": 0,
				},
			]},
		},
	}
}

# Test scenario checks for EC2 instance resource ans resource changes blocks
# Allows the config if it has allowed_ami_ids
test_ec2_whitelist_amis_good {
	in = input_value_ec2_instance("ami-0022c769")
	p := {"allowed_ami_ids": {"ami-830c94e3", "ami-0022c769"}, "actions": {"create"}}
	actual := v1.ec2_whitelist_amis with input as in
		with data.library.parameters as p
	count(actual) == 0
}

# Test scenario checks for EC2 instance resource ans resource changes blocks
# Denys the config if it does not have allowed_ami_ids
test_ec2_whitelist_amis_bad {
	in = input_value_ec2_instance("ami-0022c768")
	p := {"allowed_ami_ids": {"ami-830c94e3", "ami-0022c769"}}
	actual := v1.ec2_whitelist_amis with input as in
		with data.library.parameters as p
	count(actual) == 1
}

# Test scenario checks for EC2 launch configuration and lauch template blocks
# Allows the config if it has allowed_ami_ids
test_ec2_whitelist_amis_launch_template_launch_config_good {
	in = input_value_ec2_lauch_template_config("ami-0022c769")
	p := {"allowed_ami_ids": {"ami-830c94e3", "ami-0022c769"}, "actions": {"create"}}
	actual := v1.ec2_whitelist_amis with input as in
		with data.library.parameters as p
	count(actual) == 0
}

# Test scenario checks for EC2 launch configuration and lauch template blocks
# Denys the config if it does not have allowed_ami_ids
test_ec2_whitelist_amis_launch_template_launch_config_bad {
	in = input_value_ec2_lauch_template_config("ami-0022c700")
	p := {"allowed_ami_ids": {"ami-830c94e3", "ami-0022c769"}, "actions": {"create"}}
	actual := v1.ec2_whitelist_amis with input as in
		with data.library.parameters as p
	count(actual) == 2
}

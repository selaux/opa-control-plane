package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.without_imds_v2.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ec2.without_imds_v2.v1
import data.library.parameters

metadata_options_with_http_endpoint_only(value) := x {
	x := [{"http_endpoint": value}]
}

metadata_options_with_http_tokens_only(value) := x {
	x := [{"http_tokens": value}]
}

metadata_options_with_http_tokens_and_http_endpoint(http_tokens_value, http_endpoint_value) := x {
	x := [{
		"http_tokens": http_tokens_value,
		"http_endpoint": http_endpoint_value,
	}]
}

test_vulnerable_imds_config_launch_template_good {
	metadata := metadata_options_with_http_tokens_and_http_endpoint("required", "enabled")
	in := input_launch_template_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 0
}

test_vulnerable_imds_config_launch_template_with_bad_http_token_and_http_endpoint {
	metadata := metadata_options_with_http_tokens_and_http_endpoint("optional", "disabled")
	in := input_launch_template_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 2
}

test_vulnerable_imds_config_launch_template_with_missing_http_tokens_and_good_http_endpoint {
	metadata := metadata_options_with_http_endpoint_only("enabled")
	in := input_launch_template_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 1
}

test_vulnerable_imds_config_launch_template_with_missing_http_endpoint_and_good_http_tokens {
	metadata := metadata_options_with_http_tokens_only("required")
	in := input_launch_template_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 1
}

test_vulnerable_imds_config_launch_template_with_missing_http_endpoint_and_http_tokens {
	in := input_launch_template_without_metadata_options

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 1
}

test_vulnerable_imds_config_ec2_good {
	metadata := metadata_options_with_http_tokens_and_http_endpoint("required", "enabled")
	in := input_ec2_instance_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 0
}

test_vulnerable_imds_config_ec2_with_bad_http_token_and_http_endpoint {
	metadata := metadata_options_with_http_tokens_and_http_endpoint("optional", "disabled")
	in := input_ec2_instance_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 2
}

test_vulnerable_imds_config_ec2_with_missing_http_tokens_and_good_http_endpoint {
	metadata := metadata_options_with_http_endpoint_only("enabled")
	in := input_ec2_instance_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 1
}

test_vulnerable_imds_config_ec2_with_missing_http_endpoint_and_good_http_tokens {
	metadata := metadata_options_with_http_tokens_only("required")
	in := input_ec2_instance_with_metadata_options(metadata)

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 1
}

test_vulnerable_imds_config_ec2_with_missing_http_endpoint_and_http_tokens {
	in := input_ec2_instance_without_metadata_options

	actual := v1.vulnerable_imds_config with input as in
	count(actual) == 1
}

input_launch_template_with_metadata_options(value) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_launch_template.good_resource_1",
			"mode": "managed",
			"type": "aws_launch_template",
			"name": "good_resource_1",
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
				"image_id": null,
				"instance_initiated_shutdown_behavior": null,
				"instance_market_options": [],
				"instance_requirements": [],
				"instance_type": null,
				"kernel_id": null,
				"key_name": null,
				"license_specification": [],
				"maintenance_options": [],
				"metadata_options": value,
				"monitoring": [],
				"name": "good_resource_1",
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
			"sensitive_values": {
				"block_device_mappings": [],
				"capacity_reservation_specification": [],
				"cpu_options": [],
				"credit_specification": [],
				"elastic_gpu_specifications": [],
				"elastic_inference_accelerator": [],
				"enclave_options": [],
				"hibernation_options": [],
				"iam_instance_profile": [],
				"instance_market_options": [],
				"instance_requirements": [],
				"license_specification": [],
				"maintenance_options": [],
				"metadata_options": [{}],
				"monitoring": [],
				"network_interfaces": [],
				"placement": [],
				"private_dns_name_options": [],
				"tag_specifications": [],
				"tags_all": {},
			},
		}]}},
		"resource_changes": [{
			"address": "aws_launch_template.good_resource_1",
			"mode": "managed",
			"type": "aws_launch_template",
			"name": "good_resource_1",
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
					"image_id": null,
					"instance_initiated_shutdown_behavior": null,
					"instance_market_options": [],
					"instance_requirements": [],
					"instance_type": null,
					"kernel_id": null,
					"key_name": null,
					"license_specification": [],
					"maintenance_options": [],
					"metadata_options": value,
					"monitoring": [],
					"name": "good_resource_1",
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
				"after_unknown": {
					"arn": true,
					"block_device_mappings": [],
					"capacity_reservation_specification": [],
					"cpu_options": [],
					"credit_specification": [],
					"default_version": true,
					"elastic_gpu_specifications": [],
					"elastic_inference_accelerator": [],
					"enclave_options": [],
					"hibernation_options": [],
					"iam_instance_profile": [],
					"id": true,
					"instance_market_options": [],
					"instance_requirements": [],
					"latest_version": true,
					"license_specification": [],
					"maintenance_options": [],
					"metadata_options": [{}],
					"monitoring": [],
					"name_prefix": true,
					"network_interfaces": [],
					"placement": [],
					"private_dns_name_options": [],
					"tag_specifications": [],
					"tags_all": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"block_device_mappings": [],
					"capacity_reservation_specification": [],
					"cpu_options": [],
					"credit_specification": [],
					"elastic_gpu_specifications": [],
					"elastic_inference_accelerator": [],
					"enclave_options": [],
					"hibernation_options": [],
					"iam_instance_profile": [],
					"instance_market_options": [],
					"instance_requirements": [],
					"license_specification": [],
					"maintenance_options": [],
					"metadata_options": [{}],
					"monitoring": [],
					"network_interfaces": [],
					"placement": [],
					"private_dns_name_options": [],
					"tag_specifications": [],
					"tags_all": {},
				},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [{
				"address": "aws_launch_template.good_resource_1",
				"mode": "managed",
				"type": "aws_launch_template",
				"name": "good_resource_1",
				"provider_config_key": "aws",
				"expressions": {
					"metadata_options": [{
						"http_endpoint": {"constant_value": "enabled"},
						"http_put_response_hop_limit": {"constant_value": 1},
						"http_tokens": {"constant_value": "required"},
					}],
					"name": {"constant_value": "good_resource_1"},
				},
				"schema_version": 0,
			}]},
		},
	}
}

input_launch_template_without_metadata_options := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_launch_template.good_resource_1",
			"mode": "managed",
			"type": "aws_launch_template",
			"name": "good_resource_1",
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
				"image_id": null,
				"instance_initiated_shutdown_behavior": null,
				"instance_market_options": [],
				"instance_requirements": [],
				"instance_type": null,
				"kernel_id": null,
				"key_name": null,
				"license_specification": [],
				"maintenance_options": [],
				"monitoring": [],
				"name": "good_resource_1",
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
			"sensitive_values": {
				"block_device_mappings": [],
				"capacity_reservation_specification": [],
				"cpu_options": [],
				"credit_specification": [],
				"elastic_gpu_specifications": [],
				"elastic_inference_accelerator": [],
				"enclave_options": [],
				"hibernation_options": [],
				"iam_instance_profile": [],
				"instance_market_options": [],
				"instance_requirements": [],
				"license_specification": [],
				"maintenance_options": [],
				"metadata_options": [],
				"monitoring": [],
				"network_interfaces": [],
				"placement": [],
				"private_dns_name_options": [],
				"tag_specifications": [],
				"tags_all": {},
			},
		}]}},
		"resource_changes": [{
			"address": "aws_launch_template.good_resource_1",
			"mode": "managed",
			"type": "aws_launch_template",
			"name": "good_resource_1",
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
					"image_id": null,
					"instance_initiated_shutdown_behavior": null,
					"instance_market_options": [],
					"instance_requirements": [],
					"instance_type": null,
					"kernel_id": null,
					"key_name": null,
					"license_specification": [],
					"maintenance_options": [],
					"monitoring": [],
					"name": "good_resource_1",
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
				"after_unknown": {
					"arn": true,
					"block_device_mappings": [],
					"capacity_reservation_specification": [],
					"cpu_options": [],
					"credit_specification": [],
					"default_version": true,
					"elastic_gpu_specifications": [],
					"elastic_inference_accelerator": [],
					"enclave_options": [],
					"hibernation_options": [],
					"iam_instance_profile": [],
					"id": true,
					"instance_market_options": [],
					"instance_requirements": [],
					"latest_version": true,
					"license_specification": [],
					"maintenance_options": [],
					"metadata_options": true,
					"monitoring": [],
					"name_prefix": true,
					"network_interfaces": [],
					"placement": [],
					"private_dns_name_options": [],
					"tag_specifications": [],
					"tags_all": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"block_device_mappings": [],
					"capacity_reservation_specification": [],
					"cpu_options": [],
					"credit_specification": [],
					"elastic_gpu_specifications": [],
					"elastic_inference_accelerator": [],
					"enclave_options": [],
					"hibernation_options": [],
					"iam_instance_profile": [],
					"instance_market_options": [],
					"instance_requirements": [],
					"license_specification": [],
					"maintenance_options": [],
					"metadata_options": [],
					"monitoring": [],
					"network_interfaces": [],
					"placement": [],
					"private_dns_name_options": [],
					"tag_specifications": [],
					"tags_all": {},
				},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [{
				"address": "aws_launch_template.good_resource_1",
				"mode": "managed",
				"type": "aws_launch_template",
				"name": "good_resource_1",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "good_resource_1"}},
				"schema_version": 0,
			}]},
		},
	}
}

input_ec2_instance_with_metadata_options(value) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_instance.good_resource_1",
			"mode": "managed",
			"type": "aws_instance",
			"name": "good_resource_1",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 1,
			"values": {
				"ami": "ami-830c94e3",
				"credit_specification": [],
				"get_password_data": false,
				"hibernation": null,
				"instance_type": "t2.micro",
				"launch_template": [],
				"metadata_options": value,
				"source_dest_check": true,
				"tags": {"Name": "good_resource_1"},
				"tags_all": {"Name": "good_resource_1"},
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
				"metadata_options": [{}],
				"network_interface": [],
				"private_dns_name_options": [],
				"root_block_device": [],
				"secondary_private_ips": [],
				"security_groups": [],
				"tags": {},
				"tags_all": {},
				"vpc_security_group_ids": [],
			},
		}]}},
		"resource_changes": [{
			"address": "aws_instance.good_resource_1",
			"mode": "managed",
			"type": "aws_instance",
			"name": "good_resource_1",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"ami": "ami-830c94e3",
					"credit_specification": [],
					"get_password_data": false,
					"hibernation": null,
					"instance_type": "t2.micro",
					"launch_template": [],
					"metadata_options": value,
					"source_dest_check": true,
					"tags": {"Name": "good_resource_1"},
					"tags_all": {"Name": "good_resource_1"},
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
					"metadata_options": value,
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
					"metadata_options": [{}],
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
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [{
				"address": "aws_instance.good_resource_1",
				"mode": "managed",
				"type": "aws_instance",
				"name": "good_resource_1",
				"provider_config_key": "aws",
				"expressions": {
					"ami": {"constant_value": "ami-830c94e3"},
					"instance_type": {"constant_value": "t2.micro"},
					"metadata_options": [{
						"http_endpoint": {"constant_value": "enabled"},
						"http_tokens": {"constant_value": "required"},
					}],
					"tags": {"constant_value": {"Name": "good_resource_1"}},
				},
				"schema_version": 1,
			}]},
		},
	}
}

input_ec2_instance_without_metadata_options := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_instance.good_resource_1",
			"mode": "managed",
			"type": "aws_instance",
			"name": "good_resource_1",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 1,
			"values": {
				"ami": "ami-830c94e3",
				"credit_specification": [],
				"get_password_data": false,
				"hibernation": null,
				"instance_type": "t2.micro",
				"launch_template": [],
				"source_dest_check": true,
				"tags": {"Name": "good_resource_1"},
				"tags_all": {"Name": "good_resource_1"},
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
		}]}},
		"resource_changes": [{
			"address": "aws_instance.good_resource_1",
			"mode": "managed",
			"type": "aws_instance",
			"name": "good_resource_1",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"ami": "ami-830c94e3",
					"credit_specification": [],
					"get_password_data": false,
					"hibernation": null,
					"instance_type": "t2.micro",
					"launch_template": [],
					"source_dest_check": true,
					"tags": {"Name": "good_resource_1"},
					"tags_all": {"Name": "good_resource_1"},
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
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"expressions": {"region": {"constant_value": "us-east-1"}},
			}},
			"root_module": {"resources": [{
				"address": "aws_instance.good_resource_1",
				"mode": "managed",
				"type": "aws_instance",
				"name": "good_resource_1",
				"provider_config_key": "aws",
				"expressions": {
					"ami": {"constant_value": "ami-830c94e3"},
					"instance_type": {"constant_value": "t2.micro"},
					"tags": {"constant_value": {"Name": "good_resource_1"}},
				},
				"schema_version": 1,
			}]},
		},
	}
}

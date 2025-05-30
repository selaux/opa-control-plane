package global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.ingress_restrict_public_access.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.ingress_restrict_public_access.v1

test_ingress_public_access_sg_cidr_both_good_sg_rule_good {
	cidr_1_sg = ["10.0.0.0/30", "172.16.0.0/24"]
	cidr_2_sg = ["192.168.0.0/16", "169.254.0.0/16"]
	cidr_3_sg_rule = ["10.0.0.0/30", "169.254.0.0/16"]

	in = input_with_security_group_ingress(cidr_1_sg, cidr_2_sg, cidr_3_sg_rule)
	actual := v1.ingress_restrict_public_access with input as in

	count(actual) == 0
}

test_ingress_public_access_sg_cidr_one_bad_single_cidr_sg_rule_good {
	cidr_1_sg = ["0.0.0.0/0"]
	cidr_2_sg = ["192.168.0.0/16", "169.254.0.0/16"]
	cidr_3_sg_rule = ["10.0.0.0/30", "169.254.0.0/16"]

	in = input_with_security_group_ingress(cidr_1_sg, cidr_2_sg, cidr_3_sg_rule)
	actual := v1.ingress_restrict_public_access with input as in

	count(actual) == 1
}

test_ingress_public_access_sg_cidr_multiple_bad_one_cidr_sg_rule_good {
	cidr_1_sg = ["203.0.113.0/24", "123.201.100.39/32"]
	cidr_2_sg = ["192.168.0.0/16", "169.254.0.0/16"]
	cidr_3_sg_rule = ["10.0.0.0/30", "169.254.0.0/16"]

	in = input_with_security_group_ingress(cidr_1_sg, cidr_2_sg, cidr_3_sg_rule)
	actual := v1.ingress_restrict_public_access with input as in

	count(actual) == 2
}

test_ingress_public_access_sg_cidr_multiple_bad_multiple_cidr_sg_rule_good {
	cidr_1_sg = ["203.0.113.0/24", "169.254.0.0/16"]
	cidr_2_sg = ["19.168.0.0/16", "123.201.100.39/32"]
	cidr_3_sg_rule = ["10.0.0.0/30", "169.254.0.0/16"]

	in = input_with_security_group_ingress(cidr_1_sg, cidr_2_sg, cidr_3_sg_rule)
	actual := v1.ingress_restrict_public_access with input as in

	count(actual) == 3
}

test_ingress_public_access_sg_cidr_both_good_sg_rule_one_cidr_bad {
	cidr_1_sg = ["10.0.0.0/30", "172.16.0.0/24"]
	cidr_2_sg = ["192.168.0.0/16", "169.254.0.0/16"]
	cidr_3_sg_rule = ["101.0.0.0/30", "169.254.0.0/16"]

	in = input_with_security_group_ingress(cidr_1_sg, cidr_2_sg, cidr_3_sg_rule)
	actual := v1.ingress_restrict_public_access with input as in

	count(actual) == 1
}

test_ingress_public_access_sg_cidr_both_good_sg_rule_multiple_cidr_bad {
	cidr_1_sg = ["10.0.0.0/30", "172.16.0.0/24"]
	cidr_2_sg = ["192.168.0.0/16", "169.254.0.0/16"]
	cidr_3_sg_rule = ["101.0.0.0/30", "16.254.0.0/16"]

	in = input_with_security_group_ingress(cidr_1_sg, cidr_2_sg, cidr_3_sg_rule)
	actual := v1.ingress_restrict_public_access with input as in

	count(actual) == 2
}

input_with_security_group_ingress(cidr_1_sg, cidr_2_sg, cidr_3_sg_rule) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [
				{
					"address": "module.security_group.aws_security_group.ingress_restict_public_access",
					"mode": "managed",
					"type": "aws_security_group",
					"name": "ingress_restict_public_access",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 1,
					"values": {
						"description": "Allow TLS inbound traffic",
						"ingress": [
							{
								"cidr_blocks": cidr_1_sg,
								"description": "ingress rule 1",
								"from_port": 443,
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"protocol": "tcp",
								"security_groups": [],
								"self": false,
								"to_port": 443,
							},
							{
								"cidr_blocks": cidr_2_sg,
								"description": "ingress rule 2",
								"from_port": 443,
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"protocol": "tcp",
								"security_groups": [],
								"self": false,
								"to_port": 443,
							},
						],
						"name": "good_sg",
						"revoke_rules_on_delete": false,
						"tags": {"Name": "ingress_restict_public_access"},
						"tags_all": {"Name": "ingress_restict_public_access"},
						"timeouts": null,
					},
					"sensitive_values": {
						"egress": [],
						"ingress": [
							{
								"cidr_blocks": [
									false,
									false,
								],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
							{
								"cidr_blocks": [
									false,
									false,
								],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
						],
						"tags": {},
						"tags_all": {},
					},
				},
				{
					"address": "module.security_group.aws_security_group_rule.s3_gateway_egress",
					"mode": "managed",
					"type": "aws_security_group_rule",
					"name": "s3_gateway_egress",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 2,
					"values": {
						"cidr_blocks": cidr_3_sg_rule,
						"description": "S3 Gateway Egress",
						"from_port": 443,
						"ipv6_cidr_blocks": null,
						"prefix_list_ids": null,
						"protocol": "tcp",
						"security_group_id": "sg-123456",
						"self": false,
						"timeouts": null,
						"to_port": 443,
						"type": "ingress",
					},
					"sensitive_values": {"cidr_blocks": [false]},
				},
			],
			"address": "module.security_group",
		}]}},
		"resource_changes": [
			{
				"address": "module.security_group.aws_security_group.ingress_restict_public_access",
				"module_address": "module.security_group",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "ingress_restict_public_access",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"description": "Allow TLS inbound traffic",
						"ingress": [
							{
								"cidr_blocks": cidr_1_sg,
								"description": "ingress rule 1",
								"from_port": 443,
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"protocol": "tcp",
								"security_groups": [],
								"self": false,
								"to_port": 443,
							},
							{
								"cidr_blocks": cidr_2_sg,
								"description": "ingress rule 2",
								"from_port": 443,
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"protocol": "tcp",
								"security_groups": [],
								"self": false,
								"to_port": 443,
							},
						],
						"name": "good_sg",
						"revoke_rules_on_delete": false,
						"tags": {"Name": "ingress_restict_public_access"},
						"tags_all": {"Name": "ingress_restict_public_access"},
						"timeouts": null,
					},
					"after_unknown": {
						"arn": true,
						"egress": true,
						"id": true,
						"ingress": [
							{
								"cidr_blocks": [
									false,
									false,
								],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
							{
								"cidr_blocks": [
									false,
									false,
								],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
						],
						"name_prefix": true,
						"owner_id": true,
						"tags": {},
						"tags_all": {},
						"vpc_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"egress": [],
						"ingress": [
							{
								"cidr_blocks": [
									false,
									false,
								],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
							{
								"cidr_blocks": [
									false,
									false,
								],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
						],
						"tags": {},
						"tags_all": {},
					},
				},
			},
			{
				"address": "module.security_group.aws_security_group_rule.s3_gateway_egress",
				"module_address": "module.security_group",
				"mode": "managed",
				"type": "aws_security_group_rule",
				"name": "s3_gateway_egress",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"cidr_blocks": cidr_3_sg_rule,
						"description": "S3 Gateway Egress",
						"from_port": 443,
						"ipv6_cidr_blocks": null,
						"prefix_list_ids": null,
						"protocol": "tcp",
						"security_group_id": "sg-123456",
						"self": false,
						"timeouts": null,
						"to_port": 443,
						"type": "ingress",
					},
					"after_unknown": {
						"cidr_blocks": [false],
						"id": true,
						"security_group_rule_id": true,
						"source_security_group_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"cidr_blocks": [false]},
				},
			},
		],
		"configuration": {
			"provider_config": {"module.security_group:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.security_group",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {"module_calls": {"security_group": {
				"source": "../../../../../../modules/network/security_group",
				"module": {
					"resources": [
						{
							"address": "aws_security_group.ingress_restict_public_access",
							"mode": "managed",
							"type": "aws_security_group",
							"name": "ingress_restict_public_access",
							"provider_config_key": "module.security_group:aws",
							"expressions": {
								"description": {"constant_value": "Allow TLS inbound traffic"},
								"ingress": {"constant_value": [
									{
										"cidr_blocks": [
											"10.0.0.0/30",
											"172.16.0.0/24",
										],
										"description": "ingress rule 1",
										"from_port": 443,
										"ipv6_cidr_blocks": null,
										"prefix_list_ids": null,
										"protocol": "tcp",
										"security_groups": null,
										"self": null,
										"to_port": 443,
									},
									{
										"cidr_blocks": [
											"192.168.0.0/16",
											"169.254.0.0/16",
										],
										"description": "ingress rule 2",
										"from_port": 443,
										"ipv6_cidr_blocks": null,
										"prefix_list_ids": null,
										"protocol": "tcp",
										"security_groups": null,
										"self": null,
										"to_port": 443,
									},
								]},
								"name": {"constant_value": "good_sg"},
								"tags": {"constant_value": {"Name": "ingress_restict_public_access"}},
							},
							"schema_version": 1,
						},
						{
							"address": "aws_security_group_rule.s3_gateway_egress",
							"mode": "managed",
							"type": "aws_security_group_rule",
							"name": "s3_gateway_egress",
							"provider_config_key": "module.security_group:aws",
							"expressions": {
								"cidr_blocks": {"constant_value": ["10.10.0.0/16"]},
								"description": {"constant_value": "S3 Gateway Egress"},
								"from_port": {"constant_value": 443},
								"protocol": {"constant_value": "tcp"},
								"security_group_id": {"constant_value": "sg-123456"},
								"to_port": {"constant_value": 443},
								"type": {"constant_value": "ingress"},
							},
							"schema_version": 2,
						},
					],
					"variables": {"aws_region": {
						"default": "us-west-2",
						"description": "AWS region",
					}},
				},
			}}},
		},
	}
}

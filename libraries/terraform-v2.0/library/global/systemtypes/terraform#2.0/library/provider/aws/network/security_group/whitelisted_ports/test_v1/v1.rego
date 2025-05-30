package global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.whitelisted_ports.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.whitelisted_ports.v1

test_security_group_with_restricted_ports_good {
	in = input_with_security_group_ingress
	p := {"allowed_ports": {80, 8080, 443}}

	actual := v1.security_group_with_whitelisted_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_with_restricted_ports_good_1 {
	in = input_with_security_group_ingress
	p := {"allowed_ports": {80, 443}}

	actual := v1.security_group_with_whitelisted_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_with_restricted_ports_bad {
	in = input_with_security_group_ingress
	p := {"allowed_ports": {80, 22}}

	actual := v1.security_group_with_whitelisted_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_with_restricted_ports_bad_1 {
	in = input_with_security_group_ingress
	p := {"allowed_ports": {8080, 22}}

	actual := v1.security_group_with_whitelisted_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_with_restricted_ports_good_without_parameters {
	in = input_with_security_group_without_ingress
	p := {"allowed_ports": {}}

	actual := v1.security_group_with_whitelisted_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_with_restricted_ports_bad_without_parameters {
	in = input_with_security_group_ingress
	p := {"allowed_ports": {}}

	actual := v1.security_group_with_whitelisted_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

input_with_security_group_ingress = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.3.7",
		"variables": {"aws_region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_security_group.allow_web",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "allow_web",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 1,
				"values": {
					"description": "Allow TLS inbound traffic",
					"ingress": [
						{
							"cidr_blocks": ["0.0.0.0/0"],
							"description": "",
							"from_port": 443,
							"ipv6_cidr_blocks": [],
							"prefix_list_ids": [],
							"protocol": "tcp",
							"security_groups": [],
							"self": false,
							"to_port": 443,
						},
						{
							"cidr_blocks": ["0.0.0.0/0"],
							"description": "",
							"from_port": 80,
							"ipv6_cidr_blocks": [],
							"prefix_list_ids": [],
							"protocol": "tcp",
							"security_groups": [],
							"self": false,
							"to_port": 80,
						},
					],
					"name": "allow_web",
					"revoke_rules_on_delete": false,
					"tags": {"Name": "allow_web"},
					"tags_all": {"Name": "allow_web"},
					"timeouts": null,
				},
				"sensitive_values": {
					"egress": [],
					"ingress": [
						{
							"cidr_blocks": [false],
							"ipv6_cidr_blocks": [],
							"prefix_list_ids": [],
							"security_groups": [],
						},
						{
							"cidr_blocks": [false],
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
				"address": "aws_security_group.disallow_ingress",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "disallow_ingress",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 1,
				"values": {
					"description": "Allow TLS inbound traffic",
					"name": "allow_tls",
					"revoke_rules_on_delete": false,
					"tags": {"Name": "allow_tls"},
					"tags_all": {"Name": "allow_tls"},
					"timeouts": null,
				},
				"sensitive_values": {
					"egress": [],
					"ingress": [],
					"tags": {},
					"tags_all": {},
				},
			},
			{
				"address": "aws_security_group_rule.s3_gateway_egress",
				"mode": "managed",
				"type": "aws_security_group_rule",
				"name": "s3_gateway_egress",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 2,
				"values": {
					"cidr_blocks": ["10.10.0.0/16"],
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
		]}},
		"resource_changes": [
			{
				"address": "aws_security_group.allow_web",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "allow_web",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"description": "Allow TLS inbound traffic",
						"ingress": [
							{
								"cidr_blocks": ["0.0.0.0/0"],
								"description": "",
								"from_port": 443,
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"protocol": "tcp",
								"security_groups": [],
								"self": false,
								"to_port": 443,
							},
							{
								"cidr_blocks": ["0.0.0.0/0"],
								"description": "",
								"from_port": 80,
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"protocol": "tcp",
								"security_groups": [],
								"self": false,
								"to_port": 80,
							},
						],
						"name": "allow_web",
						"revoke_rules_on_delete": false,
						"tags": {"Name": "allow_web"},
						"tags_all": {"Name": "allow_web"},
						"timeouts": null,
					},
					"after_unknown": {
						"arn": true,
						"egress": true,
						"id": true,
						"ingress": [
							{
								"cidr_blocks": [false],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
							{
								"cidr_blocks": [false],
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
								"cidr_blocks": [false],
								"ipv6_cidr_blocks": [],
								"prefix_list_ids": [],
								"security_groups": [],
							},
							{
								"cidr_blocks": [false],
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
				"address": "aws_security_group.disallow_ingress",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "disallow_ingress",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"description": "Allow TLS inbound traffic",
						"name": "allow_tls",
						"revoke_rules_on_delete": false,
						"tags": {"Name": "allow_tls"},
						"tags_all": {"Name": "allow_tls"},
						"timeouts": null,
					},
					"after_unknown": {
						"arn": true,
						"egress": true,
						"id": true,
						"ingress": true,
						"name_prefix": true,
						"owner_id": true,
						"tags": {},
						"tags_all": {},
						"vpc_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"egress": [],
						"ingress": [],
						"tags": {},
						"tags_all": {},
					},
				},
			},
			{
				"address": "aws_security_group_rule.s3_gateway_egress",
				"mode": "managed",
				"type": "aws_security_group_rule",
				"name": "s3_gateway_egress",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"cidr_blocks": ["10.10.0.0/16"],
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
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"expressions": {"region": {"references": ["var.aws_region"]}},
			}},
			"root_module": {
				"resources": [
					{
						"address": "aws_security_group.allow_web",
						"mode": "managed",
						"type": "aws_security_group",
						"name": "allow_web",
						"provider_config_key": "aws",
						"expressions": {
							"description": {"constant_value": "Allow TLS inbound traffic"},
							"ingress": {"constant_value": [
								{
									"cidr_blocks": ["0.0.0.0/0"],
									"description": null,
									"from_port": 80,
									"ipv6_cidr_blocks": null,
									"prefix_list_ids": null,
									"protocol": "tcp",
									"security_groups": null,
									"self": null,
									"to_port": 80,
								},
								{
									"cidr_blocks": ["0.0.0.0/0"],
									"description": null,
									"from_port": 443,
									"ipv6_cidr_blocks": null,
									"prefix_list_ids": null,
									"protocol": "tcp",
									"security_groups": null,
									"self": null,
									"to_port": 443,
								},
							]},
							"name": {"constant_value": "allow_web"},
							"tags": {"constant_value": {"Name": "allow_web"}},
						},
						"schema_version": 1,
					},
					{
						"address": "aws_security_group.disallow_ingress",
						"mode": "managed",
						"type": "aws_security_group",
						"name": "disallow_ingress",
						"provider_config_key": "aws",
						"expressions": {
							"description": {"constant_value": "Allow TLS inbound traffic"},
							"name": {"constant_value": "allow_tls"},
							"tags": {"constant_value": {"Name": "allow_tls"}},
						},
						"schema_version": 1,
					},
					{
						"address": "aws_security_group_rule.s3_gateway_egress",
						"mode": "managed",
						"type": "aws_security_group_rule",
						"name": "s3_gateway_egress",
						"provider_config_key": "aws",
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
		},
	}
}

input_with_security_group_without_ingress = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_security_group.disallow_ingress",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "disallow_ingress",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Allow TLS inbound traffic",
				"name": "allow_tls",
				"revoke_rules_on_delete": false,
				"tags": {"Name": "allow_tls"},
				"timeouts": null,
			},
		}]}},
		"resource_changes": [{
			"address": "aws_security_group.disallow_ingress",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "disallow_ingress",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Allow TLS inbound traffic",
					"name": "allow_tls",
					"revoke_rules_on_delete": false,
					"tags": {"Name": "allow_tls"},
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": true,
					"name_prefix": true,
					"owner_id": true,
					"tags": {},
					"vpc_id": true,
				},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {"region": {"constant_value": "us-west-1"}},
			}},
			"root_module": {"resources": [{
				"address": "aws_security_group.disallow_ingress",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "disallow_ingress",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "Allow TLS inbound traffic"},
					"name": {"constant_value": "allow_tls"},
					"tags": {"constant_value": {"Name": "allow_tls"}},
				},
				"schema_version": 1,
			}]},
		},
	}
}

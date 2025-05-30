package global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.whitelisted_cidr_ports.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.whitelisted_cidr_ports.v1

test_security_group_with_whitelisted_cidr_and_ports_good {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "20.1.0.0/16": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_with_whitelisted_cidr_and_ports_bad_cidr_missing {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_with_whitelisted_cidr_and_ports_bad_cidr_not_in_range {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "20.1.0.0/24": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_with_whitelisted_cidr_and_ports_bad_port_missing {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443"}, "172.68.0.0/16": {"8080", "80"}, "20.1.0.0/16": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_with_whitelisted_cidr_and_ports_bad_incorrect_port {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "8080"}, "172.68.0.0/16": {"443", "8080", "80"}, "20.1.0.0/16": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_with_whitelisted_cidr_and_ports_bad_all_port_missing_from_params {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {}, "172.68.0.0/16": {}, "20.1.0.0/16": {}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_with_whitelisted_cidr_and_ports_bad_all_params_missing {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_with_whitelisted_cidr_and_ports_good_wildcard_present {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"*": {"*"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_with_whitelisted_cidr_and_ports_good_port_wildcard_present {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"*"}, "172.68.0.0/16": {"*"}, "20.1.0.0/16": {"*"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_with_whitelisted_cidr_and_ports_bad_port_with_partial_wildcard_present {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"22"}, "172.68.0.0/16": {"*"}, "20.1.0.0/16": {"*"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_with_whitelisted_cidr_and_ports_bad_with_cidr_wildcard_and_port {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "*": {"22"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_with_whitelisted_cidr_and_ports_good_with_cidr_wildcard_and_port {
	in = input_with_security_group_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "*": {"443", "80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_rule_with_whitelisted_cidr_and_ports_good {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "20.1.0.0/16": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_cidr_missing {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_cidr_not_in_range {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "20.1.0.0/24": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_port_missing {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443"}, "172.68.0.0/16": {"8080", "80"}, "20.1.0.0/16": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_incorrect_port {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "8080"}, "172.68.0.0/16": {"443", "8080", "80"}, "20.1.0.0/16": {"80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_all_port_missing_from_params {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {}, "172.68.0.0/16": {}, "20.1.0.0/16": {}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_all_params_missing {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_rule_with_whitelisted_cidr_and_ports_good_wildcard_present {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"*": {"*"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_rule_with_whitelisted_cidr_and_ports_good_port_wildcard_present {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"*"}, "172.68.0.0/16": {"*"}, "20.1.0.0/16": {"*"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_port_with_partial_wildcard_present {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"22"}, "172.68.0.0/16": {"*"}, "20.1.0.0/16": {"*"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_security_group_rule_with_whitelisted_cidr_and_ports_bad_with_cidr_wildcard_and_port {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "*": {"22"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_security_group_rule_with_whitelisted_cidr_and_ports_good_with_cidr_wildcard_and_port {
	in = input_with_security_group_rule_ingress
	p := {"allowed_cidr_ports": {"10.1.0.0/16": {"443", "80"}, "172.68.0.0/16": {"443", "8080", "80"}, "*": {"443", "80"}}}

	actual := v1.security_group_with_whitelisted_cidr_and_ports with input as in
		with data.library.parameters as p

	count(actual) == 0
}

input_with_security_group_ingress := {
	"format_version": "0.1",
	"terraform_version": "0.12.15",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_security_group.good_allow_web",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "good_allow_web",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Allow TLS inbound traffic",
				"ingress": [
					{
						"cidr_blocks": [
							"10.1.0.0/24",
							"20.1.0.0/16",
						],
						"description": "",
						"from_port": 80,
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"protocol": "tcp",
						"security_groups": [],
						"self": false,
						"to_port": 80,
					},
					{
						"cidr_blocks": ["172.68.0.0/16"],
						"description": "",
						"from_port": 443,
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"protocol": "tcp",
						"security_groups": [],
						"self": false,
						"to_port": 443,
					},
				],
				"name": "good_allow_web",
				"name_prefix": null,
				"revoke_rules_on_delete": false,
				"tags": {"Name": "good_allow_web"},
				"timeouts": null,
			},
		},
		{
			"address": "aws_security_group.good_disallow_ingress",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "good_disallow_ingress",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Allow TLS inbound traffic",
				"name": "allow_tls",
				"name_prefix": null,
				"revoke_rules_on_delete": false,
				"tags": {"Name": "allow_tls"},
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_security_group.good_allow_web",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "good_allow_web",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Allow TLS inbound traffic",
					"ingress": [
						{
							"cidr_blocks": [
								"10.1.0.0/24",
								"20.1.0.0/16",
							],
							"description": "",
							"from_port": 80,
							"ipv6_cidr_blocks": [],
							"prefix_list_ids": [],
							"protocol": "tcp",
							"security_groups": [],
							"self": false,
							"to_port": 80,
						},
						{
							"cidr_blocks": ["172.68.0.0/16"],
							"description": "",
							"from_port": 443,
							"ipv6_cidr_blocks": [],
							"prefix_list_ids": [],
							"protocol": "tcp",
							"security_groups": [],
							"self": false,
							"to_port": 443,
						},
					],
					"name": "good_allow_web",
					"name_prefix": null,
					"revoke_rules_on_delete": false,
					"tags": {"Name": "good_allow_web"},
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
							"cidr_blocks": [false],
							"ipv6_cidr_blocks": [],
							"prefix_list_ids": [],
							"security_groups": [],
						},
					],
					"owner_id": true,
					"tags": {},
					"vpc_id": true,
				},
			},
		},
		{
			"address": "aws_security_group.good_disallow_ingress",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "good_disallow_ingress",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Allow TLS inbound traffic",
					"name": "allow_tls",
					"name_prefix": null,
					"revoke_rules_on_delete": false,
					"tags": {"Name": "allow_tls"},
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": true,
					"owner_id": true,
					"tags": {},
					"vpc_id": true,
				},
			},
		},
	],
	"configuration": {
		"provider_config": {"aws": {
			"name": "aws",
			"expressions": {"region": {"constant_value": "us-west-1"}},
		}},
		"root_module": {"resources": [
			{
				"address": "aws_security_group.good_allow_web",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "good_allow_web",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "Allow TLS inbound traffic"},
					"name": {"constant_value": "good_allow_web"},
					"tags": {"constant_value": {"Name": "good_allow_web"}},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_security_group.good_disallow_ingress",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "good_disallow_ingress",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "Allow TLS inbound traffic"},
					"name": {"constant_value": "allow_tls"},
					"tags": {"constant_value": {"Name": "allow_tls"}},
				},
				"schema_version": 1,
			},
		]},
	},
}

input_with_security_group_rule_ingress := {
	"format_version": "1.1",
	"terraform_version": "1.2.3",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_security_group.blank_group",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "blank_group",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 1,
			"values": {
				"description": "Managed by Terraform",
				"name": "blank_group",
				"revoke_rules_on_delete": false,
				"tags": null,
				"timeouts": null,
			},
			"sensitive_values": {
				"egress": [],
				"ingress": [],
				"tags_all": {},
			},
		},
		{
			"address": "aws_security_group_rule.good_allow_web_443",
			"mode": "managed",
			"type": "aws_security_group_rule",
			"name": "good_allow_web_443",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 2,
			"values": {
				"cidr_blocks": ["172.68.0.0/16"],
				"description": null,
				"from_port": 443,
				"ipv6_cidr_blocks": null,
				"prefix_list_ids": null,
				"protocol": "tcp",
				"self": false,
				"timeouts": null,
				"to_port": 443,
				"type": "ingress",
			},
			"sensitive_values": {"cidr_blocks": [false]},
		},
		{
			"address": "aws_security_group_rule.good_allow_web_80",
			"mode": "managed",
			"type": "aws_security_group_rule",
			"name": "good_allow_web_80",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 2,
			"values": {
				"cidr_blocks": [
					"10.1.0.0/24",
					"20.1.0.0/16",
				],
				"description": null,
				"from_port": 80,
				"ipv6_cidr_blocks": null,
				"prefix_list_ids": null,
				"protocol": "tcp",
				"self": false,
				"timeouts": null,
				"to_port": 80,
				"type": "ingress",
			},
			"sensitive_values": {"cidr_blocks": [
				false,
				false,
			]},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_security_group.blank_group",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "blank_group",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"name": "blank_group",
					"revoke_rules_on_delete": false,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": true,
					"name_prefix": true,
					"owner_id": true,
					"tags_all": true,
					"vpc_id": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"egress": [],
					"ingress": [],
					"tags_all": {},
				},
			},
		},
		{
			"address": "aws_security_group_rule.good_allow_web_80",
			"mode": "managed",
			"type": "aws_security_group_rule",
			"name": "good_allow_web_80",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"cidr_blocks": [
						"10.1.0.0/24",
						"20.1.0.0/16",
					],
					"description": null,
					"from_port": 80,
					"ipv6_cidr_blocks": null,
					"prefix_list_ids": null,
					"protocol": "tcp",
					"self": false,
					"timeouts": null,
					"to_port": 80,
					"type": "ingress",
				},
				"after_unknown": {
					"cidr_blocks": [
						false,
						false,
					],
					"id": true,
					"security_group_id": true,
					"security_group_rule_id": true,
					"source_security_group_id": true,
				},
				"before_sensitive": false,
				"after_sensitive": {"cidr_blocks": [
					false,
					false,
				]},
			},
		},
		{
			"address": "aws_security_group_rule.good_allow_web_443",
			"mode": "managed",
			"type": "aws_security_group_rule",
			"name": "good_allow_web_443",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"cidr_blocks": ["172.68.0.0/16"],
					"description": null,
					"from_port": 443,
					"ipv6_cidr_blocks": null,
					"prefix_list_ids": null,
					"protocol": "tcp",
					"self": false,
					"timeouts": null,
					"to_port": 443,
					"type": "ingress",
				},
				"after_unknown": {
					"cidr_blocks": [false],
					"id": true,
					"security_group_id": true,
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
			"expressions": {"region": {"constant_value": "us-west-1"}},
		}},
		"root_module": {"resources": [
			{
				"address": "aws_security_group.blank_group",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "blank_group",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "blank_group"}},
				"schema_version": 1,
			},
			{
				"address": "aws_security_group_rule.good_allow_web_443",
				"mode": "managed",
				"type": "aws_security_group_rule",
				"name": "good_allow_web_443",
				"provider_config_key": "aws",
				"expressions": {
					"cidr_blocks": {"constant_value": ["172.68.0.0/16"]},
					"from_port": {"constant_value": 443},
					"protocol": {"constant_value": "tcp"},
					"security_group_id": {"references": [
						"aws_security_group.blank_group.id",
						"aws_security_group.blank_group",
					]},
					"to_port": {"constant_value": 443},
					"type": {"constant_value": "ingress"},
				},
				"schema_version": 2,
			},
			{
				"address": "aws_security_group_rule.good_allow_web_80",
				"mode": "managed",
				"type": "aws_security_group_rule",
				"name": "good_allow_web_80",
				"provider_config_key": "aws",
				"expressions": {
					"cidr_blocks": {"constant_value": [
						"10.1.0.0/24",
						"20.1.0.0/16",
					]},
					"from_port": {"constant_value": 80},
					"protocol": {"constant_value": "tcp"},
					"security_group_id": {"references": [
						"aws_security_group.blank_group.id",
						"aws_security_group.blank_group",
					]},
					"to_port": {"constant_value": 80},
					"type": {"constant_value": "ingress"},
				},
				"schema_version": 2,
			},
		]},
	},
	"relevant_attributes": [{
		"resource": "aws_security_group.blank_group",
		"attribute": ["id"],
	}],
}

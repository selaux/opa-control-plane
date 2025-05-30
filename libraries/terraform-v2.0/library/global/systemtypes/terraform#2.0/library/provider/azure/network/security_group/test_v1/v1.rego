package global.systemtypes["terraform:2.0"].library.provider.azure.network.security_group.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.azure.network.security_group.v1

########################################################
# azurerm_network_security_group unit tests
########################################################

# destination_port_range": "80" and "source_address_prefix": "*"
test_security_group_with_restricted_ports_good1 {
	input_port_range_good := [{
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "80",
		"destination_port_ranges": [],
		"direction": "Inbound",
		"name": "good_rule1",
		"priority": 103,
		"protocol": "Tcp",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
	}]

	mock = input_with_network_security_group(input_port_range_good)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 0
}

# destination_port_range": "22" and "source_address_prefix": "19.168.0.1/0"
test_security_group_with_restricted_ports_good2 {
	input_port_range_good := [
		{
			"access": "Allow",
			"description": "",
			"destination_address_prefix": "*",
			"destination_address_prefixes": [],
			"destination_application_security_group_ids": [],
			"destination_port_range": "22",
			"destination_port_ranges": [],
			"direction": "Inbound",
			"name": "good_rule2",
			"priority": 104,
			"protocol": "Tcp",
			"source_address_prefix": "19.168.0.1/0",
			"source_address_prefixes": [],
			"source_application_security_group_ids": [],
			"source_port_range": "*",
			"source_port_ranges": [],
		},
		{
			"access": "Allow",
			"description": "",
			"destination_address_prefix": "*",
			"destination_address_prefixes": [],
			"destination_application_security_group_ids": [],
			"destination_port_range": "80",
			"destination_port_ranges": [],
			"direction": "Inbound",
			"name": "good_rule1",
			"priority": 103,
			"protocol": "Tcp",
			"source_address_prefix": "*",
			"source_address_prefixes": [],
			"source_application_security_group_ids": [],
			"source_port_range": "*",
			"source_port_ranges": [],
		},
	]

	mock = input_with_network_security_group(input_port_range_good)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 0
}

# "destination_port_ranges": ["22","80"] and "source_address_prefix": "*"
test_security_group_with_restricted_ports_bad1 {
	input_port_range_bad1 := [
		{
			"access": "Allow",
			"description": "",
			"destination_address_prefix": "*",
			"destination_address_prefixes": [],
			"destination_application_security_group_ids": [],
			"destination_port_range": "",
			"destination_port_ranges": [
				"22",
				"80",
			],
			"direction": "Inbound",
			"name": "bad_rule1",
			"priority": 100,
			"protocol": "Tcp",
			"source_address_prefix": "*",
			"source_address_prefixes": [],
			"source_application_security_group_ids": [],
			"source_port_range": "*",
			"source_port_ranges": [],
		},
		{
			"access": "Allow",
			"description": "",
			"destination_address_prefix": "*",
			"destination_address_prefixes": [],
			"destination_application_security_group_ids": [],
			"destination_port_range": "80",
			"destination_port_ranges": [],
			"direction": "Inbound",
			"name": "good_rule1",
			"priority": 103,
			"protocol": "Tcp",
			"source_address_prefix": "*",
			"source_address_prefixes": [],
			"source_application_security_group_ids": [],
			"source_port_range": "*",
			"source_port_ranges": [],
		},
	]

	mock = input_with_network_security_group(input_port_range_bad1)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_ranges": ["1-100"] and "source_address_prefix": "0.0.0.0/0"
test_security_group_with_restricted_ports_bad2 {
	input_port_range_bad2 := [{
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "",
		"destination_port_ranges": ["1-100"],
		"direction": "Inbound",
		"name": "bad_rule2",
		"priority": 101,
		"protocol": "Tcp",
		"source_address_prefix": "0.0.0.0/0",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
	}]

	mock = input_with_network_security_group(input_port_range_bad2)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_range": "22" and "source_address_prefix": "*"
test_security_group_with_restricted_ports_bad3 {
	input_port_range_bad3 := [{
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "22",
		"destination_port_ranges": [],
		"direction": "Inbound",
		"name": "bad_rule3",
		"priority": 102,
		"protocol": "Tcp",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
	}]

	mock = input_with_network_security_group(input_port_range_bad3)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_ranges": ["23-30", "200-1000", "*"] and "source_address_prefix": "*"
test_security_group_with_restricted_ports_bad4 {
	input_port_range_bad4 := [{
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "",
		"destination_port_ranges": ["23-30", "200-1000", "*"],
		"direction": "Inbound",
		"name": "bad_rule4",
		"priority": 103,
		"protocol": "Tcp",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
	}]

	mock = input_with_network_security_group(input_port_range_bad4)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_range": "22" and "source_address_prefixes": ["0.0.0.0/0"]
test_security_group_with_restricted_ports_bad5 {
	input_port_range_bad5 := [{
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "22",
		"destination_port_ranges": [],
		"direction": "Inbound",
		"name": "bad_rule5",
		"priority": 103,
		"protocol": "Tcp",
		"source_address_prefix": null,
		"source_address_prefixes": ["0.0.0.0/0"],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
	}]

	mock = input_with_network_security_group(input_port_range_bad5)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_ranges": ["23-30", "200-1000", "*"] and "source_address_prefix": "Internet"
test_security_group_with_restricted_ports_bad6 {
	input_port_range_bad6 := [{
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "",
		"destination_port_ranges": ["23-30", "200-1000", "*"],
		"direction": "Inbound",
		"name": "bad_rule6",
		"priority": 103,
		"protocol": "Tcp",
		"source_address_prefix": "Internet",
		"source_address_prefixes": null,
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
	}]

	mock = input_with_network_security_group(input_port_range_bad6)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_range": "22", "destination_port_ranges": null, and "source_address_prefix": "*"
test_security_group_with_restricted_ports_bad7 {
	input_port_range_bad7 := [
		{
			"access": "Allow",
			"description": "",
			"destination_address_prefix": "*",
			"destination_address_prefixes": null,
			"destination_application_security_group_ids": null,
			"destination_port_range": "22",
			"destination_port_ranges": null,
			"direction": "Inbound",
			"name": "bad_rule3",
			"priority": 102,
			"protocol": "Tcp",
			"source_address_prefix": "*",
			"source_address_prefixes": null,
			"source_application_security_group_ids": null,
			"source_port_range": "*",
			"source_port_ranges": null,
		},
		{
			"access": "Allow",
			"description": "",
			"destination_address_prefix": "*",
			"destination_address_prefixes": [],
			"destination_application_security_group_ids": [],
			"destination_port_range": "",
			"destination_port_ranges": ["23-30", "200-1000", "*"],
			"direction": "Inbound",
			"name": "bad_rule6",
			"priority": 103,
			"protocol": "Tcp",
			"source_address_prefix": "Internet",
			"source_address_prefixes": null,
			"source_application_security_group_ids": [],
			"source_port_range": "*",
			"source_port_ranges": [],
		},
	]

	mock = input_with_network_security_group(input_port_range_bad7)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 2
}

########################################################
# azurerm_network_security_rule unit tests
########################################################

# destination_port_range": "80" and "source_address_prefix": "*"
test_security_rule_with_restricted_ports_good1 {
	input_port_range_good := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "80",
		"destination_port_ranges": [],
		"direction": "Inbound",
		"name": "good_rule1",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 103,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_good)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 0
}

# destination_port_range": "22" and "source_address_prefix": "19.168.0.1/0"
test_security_rule_with_restricted_ports_good2 {
	input_port_range_good := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "22",
		"destination_port_ranges": [],
		"direction": "Inbound",
		"name": "good_rule2",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 104,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "19.168.0.1/0",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_good)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 0
}

# "destination_port_ranges": ["22","80"] and "source_address_prefix": "*"
test_security_rule_with_restricted_ports_bad1 {
	input_port_range_bad1 := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "",
		"destination_port_ranges": [
			"22",
			"80",
		],
		"direction": "Inbound",
		"name": "bad_rule1",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 100,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_bad1)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_ranges": ["1-100"] and "source_address_prefix": "0.0.0.0/0"
test_security_rule_with_restricted_ports_bad2 {
	input_port_range_bad2 := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "",
		"destination_port_ranges": ["1-100"],
		"direction": "Inbound",
		"name": "bad_rule2",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 101,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "0.0.0.0/0",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_bad2)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_range": "22" and "source_address_prefix": "*"
test_security_rule_with_restricted_ports_bad3 {
	input_port_range_bad3 := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "22",
		"destination_port_ranges": [],
		"direction": "Inbound",
		"name": "bad_rule3",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 102,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_bad3)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_ranges": ["23-30", "200-1000", "*"] and "source_address_prefix": "*"
test_security_rule_with_restricted_ports_bad4 {
	input_port_range_bad4 := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "",
		"destination_port_ranges": ["23-30", "200-1000", "*"],
		"direction": "Inbound",
		"name": "bad_rule4",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 103,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_bad4)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_range": "22" and "source_address_prefixes": ["0.0.0.0/0"]
test_security_rule_with_restricted_ports_bad5 {
	input_port_range_bad5 := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "22",
		"destination_port_ranges": [],
		"direction": "Inbound",
		"name": "bad_rule5",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 103,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": null,
		"source_address_prefixes": ["0.0.0.0/0"],
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_bad5)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_ranges": ["23-30", "200-1000", "*"] and "source_address_prefix": "Internet"
test_security_rule_with_restricted_ports_bad6 {
	input_port_range_bad6 := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": [],
		"destination_application_security_group_ids": [],
		"destination_port_range": "",
		"destination_port_ranges": ["23-30", "200-1000", "*"],
		"direction": "Inbound",
		"name": "bad_rule6",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 103,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "Internet",
		"source_address_prefixes": null,
		"source_application_security_group_ids": [],
		"source_port_range": "*",
		"source_port_ranges": [],
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_bad6)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

# "destination_port_range": "22", "destination_port_ranges": null, and "source_address_prefix": "*"
test_security_rule_with_restricted_ports_bad7 {
	input_port_range_bad7 := {
		"access": "Allow",
		"description": "",
		"destination_address_prefix": "*",
		"destination_address_prefixes": null,
		"destination_application_security_group_ids": null,
		"destination_port_range": "22",
		"destination_port_ranges": null,
		"direction": "Inbound",
		"name": "bad_rule3",
		"network_security_group_name": "TestSecurityGroupSeparateRules",
		"priority": 102,
		"protocol": "Tcp",
		"resource_group_name": "api-rg-pro",
		"source_address_prefix": "*",
		"source_address_prefixes": null,
		"source_application_security_group_ids": null,
		"source_port_range": "*",
		"source_port_ranges": null,
		"timeouts": null,
	}

	mock = input_with_network_security_rule(input_port_range_bad7)
	actual := v1.restrict_network_security_group_for_ssh with input as mock

	count(actual) == 1
}

input_with_network_security_group(security_rule) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "azurerm_network_security_group.example",
				"mode": "managed",
				"type": "azurerm_network_security_group",
				"name": "example",
				"provider_name": "azurerm",
				"schema_version": 0,
				"values": {
					"location": "westeurope",
					"name": "acceptanceTestSecurityGroup1",
					"resource_group_name": "api-rg-pro",
					"security_rule": [security_rule],
					"tags": {"environment": "Production"},
					"timeouts": null,
				},
			},
			{
				"address": "azurerm_resource_group.example",
				"mode": "managed",
				"type": "azurerm_resource_group",
				"name": "example",
				"provider_name": "azurerm",
				"schema_version": 0,
				"values": {
					"location": "westeurope",
					"name": "api-rg-pro",
					"tags": null,
					"timeouts": null,
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "azurerm_network_security_group.example",
				"mode": "managed",
				"type": "azurerm_network_security_group",
				"name": "example",
				"provider_name": "azurerm",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"location": "westeurope",
						"name": "acceptanceTestSecurityGroup1",
						"resource_group_name": "api-rg-pro",
						"security_rule": security_rule,
						"tags": {"environment": "Production"},
						"timeouts": null,
					},
					"after_unknown": {
						"id": true,
						"security_rule": [
							{
								"destination_address_prefixes": [],
								"destination_application_security_group_ids": [],
								"destination_port_ranges": [false],
								"source_address_prefixes": [],
								"source_application_security_group_ids": [],
								"source_port_ranges": [],
							},
							{
								"destination_address_prefixes": [],
								"destination_application_security_group_ids": [],
								"destination_port_ranges": [
									false,
									false,
								],
								"source_address_prefixes": [],
								"source_application_security_group_ids": [],
								"source_port_ranges": [],
							},
							{
								"destination_address_prefixes": [],
								"destination_application_security_group_ids": [],
								"destination_port_ranges": [],
								"source_address_prefixes": [],
								"source_application_security_group_ids": [],
								"source_port_ranges": [],
							},
							{
								"destination_address_prefixes": [],
								"destination_application_security_group_ids": [],
								"destination_port_ranges": [],
								"source_address_prefixes": [],
								"source_application_security_group_ids": [],
								"source_port_ranges": [],
							},
							{
								"destination_address_prefixes": [],
								"destination_application_security_group_ids": [],
								"destination_port_ranges": [],
								"source_address_prefixes": [],
								"source_application_security_group_ids": [],
								"source_port_ranges": [],
							},
						],
						"tags": {},
					},
				},
			},
			{
				"address": "azurerm_resource_group.example",
				"mode": "managed",
				"type": "azurerm_resource_group",
				"name": "example",
				"provider_name": "azurerm",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"location": "westeurope",
						"name": "api-rg-pro",
						"tags": null,
						"timeouts": null,
					},
					"after_unknown": {"id": true},
				},
			},
		],
		"configuration": {
			"provider_config": {"azurerm": {
				"name": "azurerm",
				"expressions": {"features": [{}]},
			}},
			"root_module": {"resources": [
				{
					"address": "azurerm_network_security_group.example",
					"mode": "managed",
					"type": "azurerm_network_security_group",
					"name": "example",
					"provider_config_key": "azurerm",
					"expressions": {
						"location": {"references": ["azurerm_resource_group.example"]},
						"name": {"constant_value": "acceptanceTestSecurityGroup1"},
						"resource_group_name": {"references": ["azurerm_resource_group.example"]},
						"tags": {"constant_value": {"environment": "Production"}},
					},
					"schema_version": 0,
				},
				{
					"address": "azurerm_resource_group.example",
					"mode": "managed",
					"type": "azurerm_resource_group",
					"name": "example",
					"provider_config_key": "azurerm",
					"expressions": {
						"location": {"constant_value": "West Europe"},
						"name": {"constant_value": "api-rg-pro"},
					},
					"schema_version": 0,
				},
			]},
		},
	}
}

input_with_network_security_rule(security_rule) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.3",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "azurerm_network_security_group.separate_rules_group",
				"mode": "managed",
				"type": "azurerm_network_security_group",
				"name": "separate_rules_group",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"schema_version": 0,
				"values": {
					"location": "westeurope",
					"name": "TestSecurityGroupSeparateRules",
					"resource_group_name": "api-rg-pro",
					"tags": null,
					"timeouts": null,
				},
				"sensitive_values": {"security_rule": []},
			},
			{
				"address": "azurerm_network_security_rule.separate_rules_bad_rule1",
				"mode": "managed",
				"type": "azurerm_network_security_rule",
				"name": "separate_rules_bad_rule1",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"schema_version": 0,
				"values": {
					"access": "Allow",
					"description": null,
					"destination_address_prefix": "*",
					"destination_address_prefixes": null,
					"destination_application_security_group_ids": null,
					"destination_port_range": null,
					"destination_port_ranges": [
						"22",
						"80",
					],
					"direction": "Inbound",
					"name": "bad_rule1",
					"network_security_group_name": "TestSecurityGroupSeparateRules",
					"priority": 100,
					"protocol": "Tcp",
					"resource_group_name": "api-rg-pro",
					"source_address_prefix": "*",
					"source_address_prefixes": null,
					"source_application_security_group_ids": null,
					"source_port_range": "*",
					"source_port_ranges": null,
					"timeouts": null,
				},
				"sensitive_values": {"destination_port_ranges": [
					false,
					false,
				]},
			},
			{
				"address": "azurerm_network_security_rule.separate_rules_bad_rule2",
				"mode": "managed",
				"type": "azurerm_network_security_rule",
				"name": "separate_rules_bad_rule2",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"schema_version": 0,
				"values": {
					"access": "Allow",
					"description": null,
					"destination_address_prefix": "*",
					"destination_address_prefixes": null,
					"destination_application_security_group_ids": null,
					"destination_port_range": null,
					"destination_port_ranges": ["1-100"],
					"direction": "Inbound",
					"name": "bad_rule2",
					"network_security_group_name": "TestSecurityGroupSeparateRules",
					"priority": 101,
					"protocol": "Tcp",
					"resource_group_name": "api-rg-pro",
					"source_address_prefix": "0.0.0.0/0",
					"source_address_prefixes": null,
					"source_application_security_group_ids": null,
					"source_port_range": "*",
					"source_port_ranges": null,
					"timeouts": null,
				},
				"sensitive_values": {"destination_port_ranges": [false]},
			},
			{
				"address": "azurerm_network_security_rule.separate_rules_bad_rule3",
				"mode": "managed",
				"type": "azurerm_network_security_rule",
				"name": "separate_rules_bad_rule3",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"schema_version": 0,
				"values": {
					"access": "Allow",
					"description": null,
					"destination_address_prefix": "*",
					"destination_address_prefixes": null,
					"destination_application_security_group_ids": null,
					"destination_port_range": "22",
					"destination_port_ranges": null,
					"direction": "Inbound",
					"name": "bad_rule3",
					"network_security_group_name": "TestSecurityGroupSeparateRules",
					"priority": 102,
					"protocol": "Tcp",
					"resource_group_name": "api-rg-pro",
					"source_address_prefix": "*",
					"source_address_prefixes": null,
					"source_application_security_group_ids": null,
					"source_port_range": "*",
					"source_port_ranges": null,
					"timeouts": null,
				},
				"sensitive_values": {},
			},
			{
				"address": "azurerm_network_security_rule.separate_rules_good_rule1",
				"mode": "managed",
				"type": "azurerm_network_security_rule",
				"name": "separate_rules_good_rule1",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"schema_version": 0,
				"values": {
					"access": "Allow",
					"description": null,
					"destination_address_prefix": "*",
					"destination_address_prefixes": null,
					"destination_application_security_group_ids": null,
					"destination_port_range": "80",
					"destination_port_ranges": null,
					"direction": "Inbound",
					"name": "good_rule1",
					"network_security_group_name": "TestSecurityGroupSeparateRules",
					"priority": 103,
					"protocol": "Tcp",
					"resource_group_name": "api-rg-pro",
					"source_address_prefix": "*",
					"source_address_prefixes": null,
					"source_application_security_group_ids": null,
					"source_port_range": "*",
					"source_port_ranges": null,
					"timeouts": null,
				},
				"sensitive_values": {},
			},
			{
				"address": "azurerm_network_security_rule.separate_rules_good_rule2",
				"mode": "managed",
				"type": "azurerm_network_security_rule",
				"name": "separate_rules_good_rule2",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"schema_version": 0,
				"values": {
					"access": "Allow",
					"description": null,
					"destination_address_prefix": "*",
					"destination_address_prefixes": null,
					"destination_application_security_group_ids": null,
					"destination_port_range": "22",
					"destination_port_ranges": null,
					"direction": "Inbound",
					"name": "good_rule2",
					"network_security_group_name": "TestSecurityGroupSeparateRules",
					"priority": 104,
					"protocol": "Tcp",
					"resource_group_name": "api-rg-pro",
					"source_address_prefix": "19.168.0.1/0",
					"source_address_prefixes": null,
					"source_application_security_group_ids": null,
					"source_port_range": "*",
					"source_port_ranges": null,
					"timeouts": null,
				},
				"sensitive_values": {},
			},
			{
				"address": "azurerm_resource_group.example",
				"mode": "managed",
				"type": "azurerm_resource_group",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"schema_version": 0,
				"values": {
					"location": "westeurope",
					"name": "api-rg-pro",
					"tags": null,
					"timeouts": null,
				},
				"sensitive_values": {},
			},
		]}},
		"resource_changes": [
			{
				"address": "azurerm_network_security_group.separate_rules_group",
				"mode": "managed",
				"type": "azurerm_network_security_group",
				"name": "separate_rules_group",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"location": "westeurope",
						"name": "TestSecurityGroupSeparateRules",
						"resource_group_name": "api-rg-pro",
						"tags": null,
						"timeouts": null,
					},
					"after_unknown": {
						"id": true,
						"security_rule": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"security_rule": []},
				},
			},
			{
				"address": "azurerm_network_security_rule.separate_rule",
				"mode": "managed",
				"type": "azurerm_network_security_rule",
				"name": "separate_rule",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": security_rule,
					"after_unknown": {"id": true},
					"before_sensitive": false,
					"after_sensitive": {},
				},
			},
			{
				"address": "azurerm_resource_group.example",
				"mode": "managed",
				"type": "azurerm_resource_group",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/azurerm",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"location": "westeurope",
						"name": "api-rg-pro",
						"tags": null,
						"timeouts": null,
					},
					"after_unknown": {"id": true},
					"before_sensitive": false,
					"after_sensitive": {},
				},
			},
		],
		"configuration": {
			"provider_config": {"azurerm": {
				"name": "azurerm",
				"full_name": "registry.terraform.io/hashicorp/azurerm",
				"expressions": {"features": [{}]},
			}},
			"root_module": {"resources": [
				{
					"address": "azurerm_network_security_group.separate_rules_group",
					"mode": "managed",
					"type": "azurerm_network_security_group",
					"name": "separate_rules_group",
					"provider_config_key": "azurerm",
					"expressions": {
						"location": {"references": [
							"azurerm_resource_group.example.location",
							"azurerm_resource_group.example",
						]},
						"name": {"constant_value": "TestSecurityGroupSeparateRules"},
						"resource_group_name": {"references": [
							"azurerm_resource_group.example.name",
							"azurerm_resource_group.example",
						]},
					},
					"schema_version": 0,
				},
				{
					"address": "azurerm_network_security_rule.separate_rules_bad_rule1",
					"mode": "managed",
					"type": "azurerm_network_security_rule",
					"name": "separate_rules_bad_rule1",
					"provider_config_key": "azurerm",
					"expressions": {
						"access": {"constant_value": "Allow"},
						"destination_address_prefix": {"constant_value": "*"},
						"destination_port_ranges": {"constant_value": [
							22,
							80,
						]},
						"direction": {"constant_value": "Inbound"},
						"name": {"constant_value": "bad_rule1"},
						"network_security_group_name": {"references": [
							"azurerm_network_security_group.separate_rules_group.name",
							"azurerm_network_security_group.separate_rules_group",
						]},
						"priority": {"constant_value": 100},
						"protocol": {"constant_value": "Tcp"},
						"resource_group_name": {"references": [
							"azurerm_resource_group.example.name",
							"azurerm_resource_group.example",
						]},
						"source_address_prefix": {"constant_value": "*"},
						"source_port_range": {"constant_value": "*"},
					},
					"schema_version": 0,
				},
				{
					"address": "azurerm_network_security_rule.separate_rules_bad_rule2",
					"mode": "managed",
					"type": "azurerm_network_security_rule",
					"name": "separate_rules_bad_rule2",
					"provider_config_key": "azurerm",
					"expressions": {
						"access": {"constant_value": "Allow"},
						"destination_address_prefix": {"constant_value": "*"},
						"destination_port_ranges": {"constant_value": ["1-100"]},
						"direction": {"constant_value": "Inbound"},
						"name": {"constant_value": "bad_rule2"},
						"network_security_group_name": {"references": [
							"azurerm_network_security_group.separate_rules_group.name",
							"azurerm_network_security_group.separate_rules_group",
						]},
						"priority": {"constant_value": 101},
						"protocol": {"constant_value": "Tcp"},
						"resource_group_name": {"references": [
							"azurerm_resource_group.example.name",
							"azurerm_resource_group.example",
						]},
						"source_address_prefix": {"constant_value": "0.0.0.0/0"},
						"source_port_range": {"constant_value": "*"},
					},
					"schema_version": 0,
				},
				{
					"address": "azurerm_network_security_rule.separate_rules_bad_rule3",
					"mode": "managed",
					"type": "azurerm_network_security_rule",
					"name": "separate_rules_bad_rule3",
					"provider_config_key": "azurerm",
					"expressions": {
						"access": {"constant_value": "Allow"},
						"destination_address_prefix": {"constant_value": "*"},
						"destination_port_range": {"constant_value": "22"},
						"direction": {"constant_value": "Inbound"},
						"name": {"constant_value": "bad_rule3"},
						"network_security_group_name": {"references": [
							"azurerm_network_security_group.separate_rules_group.name",
							"azurerm_network_security_group.separate_rules_group",
						]},
						"priority": {"constant_value": 102},
						"protocol": {"constant_value": "Tcp"},
						"resource_group_name": {"references": [
							"azurerm_resource_group.example.name",
							"azurerm_resource_group.example",
						]},
						"source_address_prefix": {"constant_value": "*"},
						"source_port_range": {"constant_value": "*"},
					},
					"schema_version": 0,
				},
				{
					"address": "azurerm_network_security_rule.separate_rules_good_rule1",
					"mode": "managed",
					"type": "azurerm_network_security_rule",
					"name": "separate_rules_good_rule1",
					"provider_config_key": "azurerm",
					"expressions": {
						"access": {"constant_value": "Allow"},
						"destination_address_prefix": {"constant_value": "*"},
						"destination_port_range": {"constant_value": "80"},
						"direction": {"constant_value": "Inbound"},
						"name": {"constant_value": "good_rule1"},
						"network_security_group_name": {"references": [
							"azurerm_network_security_group.separate_rules_group.name",
							"azurerm_network_security_group.separate_rules_group",
						]},
						"priority": {"constant_value": 103},
						"protocol": {"constant_value": "Tcp"},
						"resource_group_name": {"references": [
							"azurerm_resource_group.example.name",
							"azurerm_resource_group.example",
						]},
						"source_address_prefix": {"constant_value": "*"},
						"source_port_range": {"constant_value": "*"},
					},
					"schema_version": 0,
				},
				{
					"address": "azurerm_network_security_rule.separate_rules_good_rule2",
					"mode": "managed",
					"type": "azurerm_network_security_rule",
					"name": "separate_rules_good_rule2",
					"provider_config_key": "azurerm",
					"expressions": {
						"access": {"constant_value": "Allow"},
						"destination_address_prefix": {"constant_value": "*"},
						"destination_port_range": {"constant_value": "22"},
						"direction": {"constant_value": "Inbound"},
						"name": {"constant_value": "good_rule2"},
						"network_security_group_name": {"references": [
							"azurerm_network_security_group.separate_rules_group.name",
							"azurerm_network_security_group.separate_rules_group",
						]},
						"priority": {"constant_value": 104},
						"protocol": {"constant_value": "Tcp"},
						"resource_group_name": {"references": [
							"azurerm_resource_group.example.name",
							"azurerm_resource_group.example",
						]},
						"source_address_prefix": {"constant_value": "19.168.0.1/0"},
						"source_port_range": {"constant_value": "*"},
					},
					"schema_version": 0,
				},
				{
					"address": "azurerm_resource_group.example",
					"mode": "managed",
					"type": "azurerm_resource_group",
					"name": "example",
					"provider_config_key": "azurerm",
					"expressions": {
						"location": {"constant_value": "West Europe"},
						"name": {"constant_value": "api-rg-pro"},
					},
					"schema_version": 0,
				},
			]},
		},
		"relevant_attributes": [
			{
				"resource": "azurerm_resource_group.example",
				"attribute": ["location"],
			},
			{
				"resource": "azurerm_resource_group.example",
				"attribute": ["name"],
			},
			{
				"resource": "azurerm_network_security_group.separate_rules_group",
				"attribute": ["name"],
			},
		],
	}
}

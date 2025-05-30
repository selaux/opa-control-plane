package global.systemtypes["terraform:2.0"].library.provider.azure.iam.owner_role_assignment.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.azure.iam.owner_role_assignment.v1

test_prohibit_owner_role_assignment_good {
	role_name := "Reader"
	inp := input_iam_role_assignment(role_name)
	actual := v1.prohibit_owner_role_assignment with input as inp
	count(actual) == 0
}

test_prohibit_owner_role_assignment_bad {
	role_name := "Owner"
	inp := input_iam_role_assignment(role_name)
	actual := v1.prohibit_owner_role_assignment with input as inp
	count(actual) == 1
}

input_iam_role_assignment(value) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.20",
		"planned_values": {"root_module": {"resources": [{
			"address": "azurerm_role_assignment.example",
			"mode": "managed",
			"type": "azurerm_role_assignment",
			"name": "example",
			"provider_name": "azurerm",
			"schema_version": 0,
			"values": {
				"condition": null,
				"condition_version": null,
				"description": null,
				"principal_id": "52f728fa-f2c5-45c8-a41c-fc6ac91e83e2",
				"role_definition_name": value,
				"scope": "/subscriptions/dfb685d8-584d-4816-ad7a-0656fac54248",
				"timeouts": null,
			},
		}]}},
		"resource_changes": [{
			"address": "azurerm_role_assignment.example",
			"mode": "managed",
			"type": "azurerm_role_assignment",
			"name": "example",
			"provider_name": "azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"condition": null,
					"condition_version": null,
					"description": null,
					"principal_id": "52f728fa-f2c5-45c8-a41c-fc6ac91e83e2",
					"role_definition_name": value,
					"scope": "/subscriptions/dfb685d8-584d-4816-ad7a-0656fac54248",
					"timeouts": null,
				},
				"after_unknown": {
					"id": true,
					"name": true,
					"principal_type": true,
					"role_definition_id": true,
					"skip_service_principal_aad_check": true,
				},
			},
		}],
		"prior_state": {
			"format_version": "0.1",
			"terraform_version": "0.12.20",
			"values": {"root_module": {"resources": [
				{
					"address": "data.azurerm_client_config.example",
					"mode": "data",
					"type": "azurerm_client_config",
					"name": "example",
					"provider_name": "azurerm",
					"schema_version": 0,
					"values": {
						"client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
						"id": "2021-04-05 05:36:23.289107238 +0000 UTC",
						"object_id": "52f728fa-f2c5-45c8-a41c-fc6ac91e83e2",
						"subscription_id": "dfb685d8-584d-4816-ad7a-0656fac54248",
						"tenant_id": "fb056184-1d54-4e2d-9590-5ed027410118",
						"timeouts": null,
					},
				},
				{
					"address": "data.azurerm_subscription.primary",
					"mode": "data",
					"type": "azurerm_subscription",
					"name": "primary",
					"provider_name": "azurerm",
					"schema_version": 0,
					"values": {
						"display_name": "Free Trial",
						"id": "/subscriptions/dfb685d8-584d-4816-ad7a-0656fac54248",
						"location_placement_id": "PublicAndIndia_2015-09-01",
						"quota_id": "FreeTrial_2014-09-01",
						"spending_limit": "On",
						"state": "Enabled",
						"subscription_id": "dfb685d8-584d-4816-ad7a-0656fac54248",
						"tags": {},
						"tenant_id": "fb056184-1d54-4e2d-9590-5ed027410118",
						"timeouts": null,
					},
				},
			]}},
		},
		"configuration": {
			"provider_config": {"azurerm": {
				"name": "azurerm",
				"expressions": {"features": [{}]},
			}},
			"root_module": {"resources": [
				{
					"address": "azurerm_role_assignment.example",
					"mode": "managed",
					"type": "azurerm_role_assignment",
					"name": "example",
					"provider_config_key": "azurerm",
					"expressions": {
						"principal_id": {"references": ["data.azurerm_client_config.example"]},
						"role_definition_name": {"constant_value": value},
						"scope": {"references": ["data.azurerm_subscription.primary"]},
					},
					"schema_version": 0,
				},
				{
					"address": "data.azurerm_client_config.example",
					"mode": "data",
					"type": "azurerm_client_config",
					"name": "example",
					"provider_config_key": "azurerm",
					"schema_version": 0,
				},
				{
					"address": "data.azurerm_subscription.primary",
					"mode": "data",
					"type": "azurerm_subscription",
					"name": "primary",
					"provider_config_key": "azurerm",
					"schema_version": 0,
				},
			]},
		},
	}
}

package global.systemtypes["terraform:2.0"].library.provider.azure.mysql_db.backup_disabled.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.azure.mysql_db.backup_disabled.v1

test_prohibit_backup_disabled_mysql_db_server_good {
	db := input_db(true)
	actual := v1.prohibit_backup_disabled_mysql_db_server with input as db

	count(actual) == 0
}

test_prohibit_backup_disabled_mysql_db_server_bad {
	db := input_db(false)
	actual := v1.prohibit_backup_disabled_mysql_db_server with input as db

	count(actual) == 1
}

test_prohibit_backup_disabled_mysql_db_server_undefined {
	db := input_db_undefined
	actual := v1.prohibit_backup_disabled_mysql_db_server with input as db

	count(actual) == 1
}

input_db(value) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "azurerm_mysql_server.example",
				"mode": "managed",
				"type": "azurerm_mysql_server",
				"name": "example",
				"provider_name": "azurerm",
				"schema_version": 0,
				"values": {
					"administrator_login": "mysqladminun",
					"administrator_login_password": "H@Sh1CoR3!",
					"auto_grow_enabled": true,
					"backup_retention_days": 7,
					"create_mode": "Default",
					"creation_source_server_id": null,
					"geo_redundant_backup_enabled": value,
					"identity": [],
					"infrastructure_encryption_enabled": false,
					"location": "westeurope",
					"name": "example-mysqlserver",
					"public_network_access_enabled": true,
					"resource_group_name": "api-rg-pro",
					"restore_point_in_time": null,
					"sku_name": "B_Gen5_2",
					"ssl_enforcement_enabled": true,
					"ssl_minimal_tls_version_enforced": "TLS1_2",
					"storage_mb": 5120,
					"tags": null,
					"threat_detection_policy": [],
					"timeouts": null,
					"version": "5.7",
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
				"address": "azurerm_mysql_server.example",
				"mode": "managed",
				"type": "azurerm_mysql_server",
				"name": "example",
				"provider_name": "azurerm",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"administrator_login": "mysqladminun",
						"administrator_login_password": "H@Sh1CoR3!",
						"auto_grow_enabled": true,
						"backup_retention_days": 7,
						"create_mode": "Default",
						"creation_source_server_id": null,
						"geo_redundant_backup_enabled": value,
						"identity": [],
						"infrastructure_encryption_enabled": false,
						"location": "westeurope",
						"name": "example-mysqlserver",
						"public_network_access_enabled": true,
						"resource_group_name": "api-rg-pro",
						"restore_point_in_time": null,
						"sku_name": "B_Gen5_2",
						"ssl_enforcement_enabled": true,
						"ssl_minimal_tls_version_enforced": "TLS1_2",
						"storage_mb": 5120,
						"tags": null,
						"threat_detection_policy": [],
						"timeouts": null,
						"version": "5.7",
					},
					"after_unknown": {
						"fqdn": true,
						"id": true,
						"identity": [],
						"ssl_enforcement": true,
						"storage_profile": true,
						"threat_detection_policy": [],
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
					"address": "azurerm_mysql_server.example",
					"mode": "managed",
					"type": "azurerm_mysql_server",
					"name": "example",
					"provider_config_key": "azurerm",
					"expressions": {
						"administrator_login": {"constant_value": "mysqladminun"},
						"administrator_login_password": {"constant_value": "H@Sh1CoR3!"},
						"auto_grow_enabled": {"constant_value": true},
						"backup_retention_days": {"constant_value": 7},
						"geo_redundant_backup_enabled": {"constant_value": true},
						"infrastructure_encryption_enabled": {"constant_value": false},
						"location": {"references": ["azurerm_resource_group.example"]},
						"name": {"constant_value": "example-mysqlserver"},
						"public_network_access_enabled": {"constant_value": true},
						"resource_group_name": {"references": ["azurerm_resource_group.example"]},
						"sku_name": {"constant_value": "B_Gen5_2"},
						"ssl_enforcement_enabled": {"constant_value": true},
						"ssl_minimal_tls_version_enforced": {"constant_value": "TLS1_2"},
						"storage_mb": {"constant_value": 5120},
						"version": {"constant_value": "5.7"},
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

input_db_undefined = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "azurerm_mysql_server.example",
				"mode": "managed",
				"type": "azurerm_mysql_server",
				"name": "example",
				"provider_name": "azurerm",
				"schema_version": 0,
				"values": {
					"administrator_login": "mysqladminun",
					"administrator_login_password": "H@Sh1CoR3!",
					"auto_grow_enabled": true,
					"backup_retention_days": 7,
					"create_mode": "Default",
					"creation_source_server_id": null,
					"identity": [],
					"infrastructure_encryption_enabled": false,
					"location": "westeurope",
					"name": "example-mysqlserver",
					"public_network_access_enabled": true,
					"resource_group_name": "api-rg-pro",
					"restore_point_in_time": null,
					"sku_name": "B_Gen5_2",
					"ssl_enforcement_enabled": true,
					"ssl_minimal_tls_version_enforced": "TLS1_2",
					"storage_mb": 5120,
					"tags": null,
					"threat_detection_policy": [],
					"timeouts": null,
					"version": "5.7",
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
				"address": "azurerm_mysql_server.example",
				"mode": "managed",
				"type": "azurerm_mysql_server",
				"name": "example",
				"provider_name": "azurerm",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"administrator_login": "mysqladminun",
						"administrator_login_password": "H@Sh1CoR3!",
						"auto_grow_enabled": true,
						"backup_retention_days": 7,
						"create_mode": "Default",
						"creation_source_server_id": null,
						"identity": [],
						"infrastructure_encryption_enabled": false,
						"location": "westeurope",
						"name": "example-mysqlserver",
						"public_network_access_enabled": true,
						"resource_group_name": "api-rg-pro",
						"restore_point_in_time": null,
						"sku_name": "B_Gen5_2",
						"ssl_enforcement_enabled": true,
						"ssl_minimal_tls_version_enforced": "TLS1_2",
						"storage_mb": 5120,
						"tags": null,
						"threat_detection_policy": [],
						"timeouts": null,
						"version": "5.7",
					},
					"after_unknown": {
						"fqdn": true,
						"id": true,
						"identity": [],
						"ssl_enforcement": true,
						"storage_profile": true,
						"threat_detection_policy": [],
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
					"address": "azurerm_mysql_server.example",
					"mode": "managed",
					"type": "azurerm_mysql_server",
					"name": "example",
					"provider_config_key": "azurerm",
					"expressions": {
						"administrator_login": {"constant_value": "mysqladminun"},
						"administrator_login_password": {"constant_value": "H@Sh1CoR3!"},
						"auto_grow_enabled": {"constant_value": true},
						"backup_retention_days": {"constant_value": 7},
						"geo_redundant_backup_enabled": {"constant_value": true},
						"infrastructure_encryption_enabled": {"constant_value": false},
						"location": {"references": ["azurerm_resource_group.example"]},
						"name": {"constant_value": "example-mysqlserver"},
						"public_network_access_enabled": {"constant_value": true},
						"resource_group_name": {"references": ["azurerm_resource_group.example"]},
						"sku_name": {"constant_value": "B_Gen5_2"},
						"ssl_enforcement_enabled": {"constant_value": true},
						"ssl_minimal_tls_version_enforced": {"constant_value": "TLS1_2"},
						"storage_mb": {"constant_value": 5120},
						"version": {"constant_value": "5.7"},
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

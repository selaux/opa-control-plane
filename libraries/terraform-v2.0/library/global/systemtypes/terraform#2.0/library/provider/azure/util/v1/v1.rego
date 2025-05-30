package global.systemtypes["terraform:2.0"].library.provider.azure.util.v1

import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# Helper rules for Azure resources in the resource_changes plan object

mariadb_server_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "azurerm_mariadb_server"
}

mysql_server_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "azurerm_mysql_server"
}

network_security_group_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "azurerm_network_security_group"
}

network_security_rule_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "azurerm_network_security_rule"
}

postgres_server_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "azurerm_postgresql_server"
}

role_assignment_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "azurerm_role_assignment"
}

storage_account_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "azurerm_storage_account"
}

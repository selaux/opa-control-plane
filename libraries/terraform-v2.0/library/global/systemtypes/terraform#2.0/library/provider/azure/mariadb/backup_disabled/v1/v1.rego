package global.systemtypes["terraform:2.0"].library.provider.azure.mariadb.backup_disabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.azure.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Azure: MariaDB: Prohibit backup disabled MariaDB database"
# description: >-
#   Require Azure/MariaDB database to have Geo-redundant backup enabled.
# severity: "medium"
# platform: "terraform"
# resource-type: "azure-mariadb"
# custom:
#   id: "azure.mariadb.backup_disabled"
#   impact: ""
#   remediation: ""
#   severity: "medium"
#   resource_category: ""
#   control_category: ""
#   rule_link: "https://docs.styra.com/systems/terraform/snippets"
#   platform:
#     name: "terraform"
#     versions:
#       min: "v0.12"
#       max: "v1.3"
#   provider:
#     name: "azurerm"
#     versions:
#       min: "v2"
#       max: "v3"
#   rule_targets:
#     - { scope: "resource", service: "mariadb", name: "mariadb_server", identifier: "azurerm_mariadb_server", argument: "geo_redundant_backup_enabled" }
# schema:
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "violation.message"
#     - type: rego
#       key: metadata
#       value: "violation.metadata"
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[violation]"
prohibit_backup_disabled_mariadb_db_server[violation] {
	backup_disabled_database[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

backup_disabled_database[violation] {
	azure_database := util.mariadb_server_resource_changes[_]
	azure_database.change.after.geo_redundant_backup_enabled == false

	violation := {
		"message": sprintf("MariaDB Database %v without geo redundant backup is prohibited.", [azure_database.address]),
		"resource": azure_database,
		"context": {"geo_redundant_backup_enabled": azure_database.change.after.geo_redundant_backup_enabled},
	}
}

backup_disabled_database[violation] {
	azure_database := util.mariadb_server_resource_changes[_]
	not utils.is_key_defined(azure_database.change.after, "geo_redundant_backup_enabled")

	violation := {
		"message": sprintf("MariaDB Database %v without geo redundant backup is prohibited.", [azure_database.address]),
		"resource": azure_database,
		"context": {"geo_redundant_backup_enabled": "undefined"},
	}
}

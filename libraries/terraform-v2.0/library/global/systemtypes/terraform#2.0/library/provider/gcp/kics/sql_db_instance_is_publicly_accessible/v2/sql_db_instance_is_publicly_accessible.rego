package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.sql_db_instance_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

sql_db_instance_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.google_sql_database_instance[name]
	ip_configuration := resource.settings.ip_configuration
	count(ip_configuration.authorized_networks) > 0
	authorized_network = getAuthorizedNetworks(ip_configuration.authorized_networks)
	contains(authorized_network[j].value, "0.0.0.0")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'authorized_network' address is not restricted: '0.0.0.0/0'", "keyExpectedValue": "'authorized_network' address should be trusted", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_sql_database_instance", "searchKey": sprintf("google_sql_database_instance[%s].settings.ip_configuration.authorized_networks.value=%s", [name, authorized_network[j].value])}
}

sql_db_instance_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.google_sql_database_instance[name]
	ip_configuration := resource.settings.ip_configuration
	not common_lib.valid_key(ip_configuration, "authorized_networks")
	ip_configuration.ipv4_enabled
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'ipv4_enabled' is enabled when there are no authorized networks", "keyExpectedValue": "'ipv4_enabled' should be disabled and 'private_network' should be defined when there are no authorized networks", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_sql_database_instance", "searchKey": sprintf("google_sql_database_instance[%s].settings.ip_configuration.ipv4_enabled", [name])}
}

sql_db_instance_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.google_sql_database_instance[name]
	ip_configuration := resource.settings.ip_configuration
	not common_lib.valid_key(ip_configuration, "authorized_networks")
	not ip_configuration.ipv4_enabled
	not common_lib.valid_key(ip_configuration, "private_network")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'private_network' is not defined when there are no authorized networks", "keyExpectedValue": "'ipv4_enabled' should be disabled and 'private_network' should be defined when there are no authorized networks", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_sql_database_instance", "searchKey": sprintf("google_sql_database_instance[%s].settings.ip_configuration", [name])}
}

sql_db_instance_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.google_sql_database_instance[name]
	settings := resource.settings
	not common_lib.valid_key(settings, "ip_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'ip_configuration' is not defined", "keyExpectedValue": "'ip_configuration' should be defined and allow only trusted networks", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_sql_database_instance", "searchKey": sprintf("google_sql_database_instance[%s].settings", [name])}
}

getAuthorizedNetworks(networks) = list {
	is_array(networks)
	list := networks
} else = list {
	is_object(networks)
	list := [networks]
} else = null

# METADATA: library-snippet
# version: v1
# title: "KICS: SQL DB Instance Publicly Accessible"
# description: >-
#   Cloud SQL instances should not be publicly accessible.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.sql_db_instance_is_publicly_accessible"
#   impact: ""
#   remediation: ""
#   severity: "high"
#   resource_category: ""
#   control_category: ""
#   rule_link: "https://docs.styra.com/systems/terraform/snippets"
#   platform:
#     name: "terraform"
#     versions:
#       min: "v0.12"
#       max: "v1.3"
#   provider:
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: google_sql_database_instance
#       name: ""
#       scope: resource
#       service: ""
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
sql_db_instance_is_publicly_accessible_snippet[violation] {
	sql_db_instance_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

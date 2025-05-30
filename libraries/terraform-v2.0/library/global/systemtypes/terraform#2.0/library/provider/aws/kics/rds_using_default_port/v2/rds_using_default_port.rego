package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rds_using_default_port.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rds_using_default_port_inner[result] {
	db := input.document[i].resource.aws_db_instance[name]
	enginePort := common_lib.engines[e]
	db.engine == e
	db.port == enginePort
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_db_instance[%s].port is set to %d", [name, enginePort]), "keyExpectedValue": sprintf("aws_db_instance[%s].port should not be set to %d", [name, enginePort]), "resourceName": tf_lib.get_resource_name(db, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].port", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "port"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDS Using Default Port"
# description: >-
#   RDS should not use the default port (an attacker can easily guess the port). For engines related to Aurora, MariaDB or MySQL, the default port is 3306. PostgreSQL default port is 5432, Oracle default port is 1521 and SQL Server default port is 1433
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rds_using_default_port"
#   impact: ""
#   remediation: ""
#   severity: "low"
#   resource_category: ""
#   control_category: ""
#   rule_link: "https://docs.styra.com/systems/terraform/snippets"
#   platform:
#     name: "terraform"
#     versions:
#       min: "v0.12"
#       max: "v1.3"
#   provider:
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: aws_db_instance
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
rds_using_default_port_snippet[violation] {
	rds_using_default_port_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

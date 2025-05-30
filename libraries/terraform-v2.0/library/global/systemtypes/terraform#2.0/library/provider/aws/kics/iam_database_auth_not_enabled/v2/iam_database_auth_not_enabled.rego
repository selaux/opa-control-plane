package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_database_auth_not_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_database_auth_not_enabled_inner[result] {
	resource := input.document[i].resource.aws_db_instance[name]
	resource.iam_database_authentication_enabled == false
	common_lib.valid_for_iam_engine_and_version_check(resource, "engine", "engine_version", "instance_class")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'iam_database_authentication_enabled' is set to false", "keyExpectedValue": "'iam_database_authentication_enabled' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].iam_database_authentication_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "iam_database_authentication_enabled"], [])}
}

iam_database_auth_not_enabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "iam_database_authentication_enabled")
	module[keyToCheck] == false
	common_lib.valid_for_iam_engine_and_version_check(module, "engine", "engine_version", "instance_class")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'iam_database_authentication_enabled' is set to false", "keyExpectedValue": "'iam_database_authentication_enabled' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].iam_database_authentication_enabled", [name]), "searchLine": common_lib.build_search_line(["module", name, "iam_database_authentication_enabled"], [])}
}

iam_database_auth_not_enabled_inner[result] {
	resource := input.document[i].resource.aws_db_instance[name]
	not common_lib.valid_key(resource, "iam_database_authentication_enabled")
	common_lib.valid_for_iam_engine_and_version_check(resource, "engine", "engine_version", "instance_class")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'iam_database_authentication_enabled' is undefined or null", "keyExpectedValue": "'iam_database_authentication_enabled' should be set to true", "remediation": "iam_database_authentication_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name], [])}
}

iam_database_auth_not_enabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "iam_database_authentication_enabled")
	not common_lib.valid_key(module, keyToCheck)
	common_lib.valid_for_iam_engine_and_version_check(module, "engine", "engine_version", "instance_class")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'iam_database_authentication_enabled' is undefined or null", "keyExpectedValue": "'iam_database_authentication_enabled' should be set to true", "remediation": "iam_database_authentication_enabled = true", "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Database Auth Not Enabled"
# description: >-
#   IAM Database Auth Enabled should be configured to true when using compatible engine and version
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_database_auth_not_enabled"
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
iam_database_auth_not_enabled_snippet[violation] {
	iam_database_auth_not_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

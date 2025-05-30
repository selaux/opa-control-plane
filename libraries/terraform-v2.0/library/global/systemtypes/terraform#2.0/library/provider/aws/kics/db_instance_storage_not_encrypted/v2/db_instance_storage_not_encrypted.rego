package global.systemtypes["terraform:2.0"].library.provider.aws.kics.db_instance_storage_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

db_instance_storage_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_db_instance[name]
	resource.storage_encrypted == false
	not common_lib.valid_key(resource, "kms_key_id")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'storage_encrypted' is set to false", "keyExpectedValue": "'storage_encrypted' should be set to true", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].storage_encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "storage_encrypted"], [])}
}

db_instance_storage_not_encrypted_inner[result] {
	module := input.document[i].module[name]
	keyToCheck1 := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "storage_encrypted")
	keyToCheck2 := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "kms_key_id")
	module[keyToCheck1] == false
	not common_lib.valid_key(module, keyToCheck2)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'storage_encrypted' is set to false", "keyExpectedValue": "'storage_encrypted' should be set to true", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].storage_encrypted", [name]), "searchLine": common_lib.build_search_line(["module", name, "storage_encrypted"], [])}
}

db_instance_storage_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_db_instance[name]
	not common_lib.valid_key(resource, "storage_encrypted")
	not common_lib.valid_key(resource, "kms_key_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'storage_encrypted' is undefined or null", "keyExpectedValue": "'storage_encrypted' should be set to true", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name], [])}
}

db_instance_storage_not_encrypted_inner[result] {
	module := input.document[i].module[name]
	keyToCheck1 := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "storage_encrypted")
	keyToCheck2 := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "kms_key_id")
	not common_lib.valid_key(module, keyToCheck1)
	not common_lib.valid_key(module, keyToCheck2)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'storage_encrypted' is undefined or null", "keyExpectedValue": "'storage_encrypted' should be set to true", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DB Instance Storage Not Encrypted"
# description: >-
#   AWS DB Instance should have its storage encrypted by setting the parameter to 'true'. The storage_encrypted default value is 'false'.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.db_instance_storage_not_encrypted"
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
db_instance_storage_not_encrypted_snippet[violation] {
	db_instance_storage_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

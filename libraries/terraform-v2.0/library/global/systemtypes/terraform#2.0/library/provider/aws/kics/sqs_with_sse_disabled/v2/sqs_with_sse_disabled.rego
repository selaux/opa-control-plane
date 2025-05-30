package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sqs_with_sse_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

## two ways to activated SSE : kms_master_key_id OR sqs_managed_sse_enabled
## https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse
sse_activated(obj) {
	common_lib.valid_key(obj, "kms_master_key_id")
} else {
	common_lib.valid_key(obj, "sqs_managed_sse_enabled")
} else = false

sqs_with_sse_disabled_inner[result] {
	resource := input.document[i].resource.aws_sqs_queue[name]
	not common_lib.valid_key(resource, "kms_master_key_id")
	resource.sqs_managed_sse_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_sqs_queue[%s].sqs_managed_sse_enabled is set to false", [name]), "keyExpectedValue": sprintf("aws_sqs_queue[%s].sqs_managed_sse_enabled must be set to true", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sqs_queue", "searchKey": sprintf("aws_sqs_queue[%s].sqs_managed_sse_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue", name, "sqs_managed_sse_enabled"], [])}
}

sqs_with_sse_disabled_inner[result] {
	resource := input.document[i].resource.aws_sqs_queue[name]
	sse_activated(resource) == false
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_sqs_queue[%s].kms_master_key_id and aws_sqs_queue[%s].sqs_managed_sse_enabled are undefined or null", [name, name]), "keyExpectedValue": sprintf("aws_sqs_queue[%s].kms_master_key_id or aws_sqs_queue[%s].sqs_managed_sse_enabled should be defined and not null", [name, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sqs_queue", "searchKey": sprintf("aws_sqs_queue[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue", name], [])}
}

sqs_with_sse_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue", "kms_master_key_id")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'kms_master_key_id' is undefined or null", "keyExpectedValue": "'kms_master_key_id' should be defined and not null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

sqs_with_sse_disabled_inner[result] {
	resource := input.document[i].resource.aws_sqs_queue[name]
	resource.kms_master_key_id == ""
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_sqs_queue.kms_master_key_id is ''", "keyExpectedValue": "aws_sqs_queue.kms_master_key_id should not be ''", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sqs_queue", "searchKey": sprintf("aws_sqs_queue[%s].kms_master_key_id", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue", name, "kms_master_key_id"], [])}
}

sqs_with_sse_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue", "kms_master_key_id")
	module[keyToCheck] == ""
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'kms_master_key_id' is empty", "keyExpectedValue": "'kms_master_key_id' should not be empty", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name, "kms_master_key_id"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQS With SSE Disabled"
# description: >-
#   Amazon Simple Queue Service (SQS) queue should protect the contents of their messages using Server-Side Encryption (SSE)
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sqs_with_sse_disabled"
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
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: aws_sqs_queue
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
sqs_with_sse_disabled_snippet[violation] {
	sqs_with_sse_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

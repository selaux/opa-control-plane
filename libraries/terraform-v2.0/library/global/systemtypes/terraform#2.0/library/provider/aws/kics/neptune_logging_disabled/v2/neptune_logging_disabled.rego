package global.systemtypes["terraform:2.0"].library.provider.aws.kics.neptune_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

validTypes := {"audit"}

validTypeConcat := concat(", ", validTypes)

neptune_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_neptune_cluster[name]
	not exist(resource, "enable_cloudwatch_logs_exports")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_neptune_cluster.enable_cloudwatch_logs_exports is undefined", "keyExpectedValue": "aws_neptune_cluster.enable_cloudwatch_logs_exports should be defined", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_neptune_cluster", "searchKey": sprintf("aws_neptune_cluster[{{%s}}]", [name])}
}

neptune_logging_disabled_inner[result] {
	logs := input.document[i].resource.aws_neptune_cluster[name].enable_cloudwatch_logs_exports
	tf_lib.empty_array(logs)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_neptune_cluster.enable_cloudwatch_logs_exports is empty", "keyExpectedValue": sprintf("aws_neptune_cluster.enable_cloudwatch_logs_exports should have all following values: %s", [validTypeConcat]), "resourceName": tf_lib.get_resource_name(input.document[i].resource.aws_neptune_cluster[name], name), "resourceType": "aws_neptune_cluster", "searchKey": sprintf("aws_neptune_cluster[{{%s}}].enable_cloudwatch_logs_exports", [name])}
}

neptune_logging_disabled_inner[result] {
	logs := input.document[i].resource.aws_neptune_cluster[name].enable_cloudwatch_logs_exports
	not tf_lib.empty_array(logs)
	logsSet := {log | log := logs[_]}
	missingTypes := validTypes - logsSet
	count(missingTypes) > 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_neptune_cluster.enable_cloudwatch_logs_exports has the following missing values: %s", [concat(", ", missingTypes)]), "keyExpectedValue": sprintf("aws_neptune_cluster.enable_cloudwatch_logs_exports should have all following values: %s", [validTypeConcat]), "resourceName": tf_lib.get_resource_name(input.document[i].resource.aws_neptune_cluster[name], name), "resourceType": "aws_neptune_cluster", "searchKey": sprintf("aws_neptune_cluster[{{%s}}].enable_cloudwatch_logs_exports", [name])}
}

exist(obj, key) {
	_ = obj[key]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Neptune Logging Is Disabled"
# description: >-
#   Neptune logging should be enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.neptune_logging_disabled"
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
#       identifier: aws_neptune_cluster
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
neptune_logging_disabled_snippet[violation] {
	neptune_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

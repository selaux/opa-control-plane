package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elb_access_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elb_access_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_elb[name]
	not common_lib.valid_key(resource, "access_logs")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_elb[{{%s}}].access_logs' is undefined or null", [name]), "keyExpectedValue": sprintf("'aws_elb[{{%s}}].access_logs' should be defined and not null", [name]), "remediation": "access_logs {\n\t\tenabled = true\n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_elb", "searchKey": sprintf("aws_elb[{{%s}}]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elb", name], [])}
}

elb_access_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_elb[name]
	logsEnabled := resource.access_logs.enabled
	logsEnabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_elb[{{%s}}].access_logs.enabled' is false", [name]), "keyExpectedValue": sprintf("'aws_elb[{{%s}}].access_logs.enabled' should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_elb", "searchKey": sprintf("aws_elb[{{%s}}].access_logs.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elb", name, "access_logs", "enabled"], [])}
}

elb_access_logging_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elb", "access_logs")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'access_logs' is undefined or null", "keyExpectedValue": "'access_logs' should be defined and not null", "remediation": sprintf("%s {\n\t\tenabled = true\n\t}", [keyToCheck]), "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

elb_access_logging_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_elb", "access_logs")
	logsEnabled := input.document[i].module[name]
	logsEnabled[keyToCheck].enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'access_logs.enabled' is false", "keyExpectedValue": "'access_logs.enabled' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s.enabled", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck, "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ELB Access Log Disabled"
# description: >-
#   ELB should have logging enabled to help on error investigation
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elb_access_logging_disabled"
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
#       identifier: aws_elb
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
elb_access_logging_disabled_snippet[violation] {
	elb_access_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

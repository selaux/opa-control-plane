package global.systemtypes["terraform:2.0"].library.provider.aws.kics.db_instance_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

db_instance_publicly_accessible_inner[result] {
	resource := input.document[i].resource.aws_db_instance[name]
	resource.publicly_accessible
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'publicly_accessible' is set to true", "keyExpectedValue": "'publicly_accessible' should be set to false or undefined", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].publicly_accessible", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "publicly_accessibled"], [])}
}

db_instance_publicly_accessible_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "publicly_accessible")
	module[keyToCheck]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'publicly_accessible' is set to true", "keyExpectedValue": "'publicly_accessible' should be set to false or undefined", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].publicly_accessible", [name]), "searchLine": common_lib.build_search_line(["module", name, "publicly_accessible"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DB Instance Publicly Accessible"
# description: >-
#   RDS must not be defined with public interface, which means the field 'publicly_accessible' should not be set to 'true' (default is 'false').
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.db_instance_publicly_accessible"
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
db_instance_publicly_accessible_snippet[violation] {
	db_instance_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ca_certificate_identifier_is_outdated.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ca_certificate_identifier_is_outdated_inner[result] {
	resource := input.document[i].resource.aws_db_instance[name]
	resource.ca_cert_identifier != "rds-ca-2019"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_db_instance.ca_cert_identifier' is '%s'", [resource.ca_cert_identifier]), "keyExpectedValue": "'aws_db_instance.ca_cert_identifier' should be 'rds-ca-2019'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].ca_cert_identifier", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "ca_cert_identifier"], [])}
}

ca_certificate_identifier_is_outdated_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "ca_cert_identifier")
	module[keyToCheck] != "rds-ca-2019"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'ca_cert_identifier' is '%s'", [module.ca_cert_identifier]), "keyExpectedValue": "'ca_cert_identifier' should be 'rds-ca-2019'", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].ca_cert_identifier", [name]), "searchLine": common_lib.build_search_line(["module", name, "ca_cert_identifier"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CA Certificate Identifier Is Outdated"
# description: >-
#   The CA certificate Identifier must be 'rds-ca-2019'.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ca_certificate_identifier_is_outdated"
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
ca_certificate_identifier_is_outdated_snippet[violation] {
	ca_certificate_identifier_is_outdated_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

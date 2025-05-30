package global.systemtypes["terraform:2.0"].library.provider.aws.kics.security_group_rules_without_description.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

security_group_rules_without_description_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	types := {"egress", "ingress"}
	resourceType := resource[types[y]]
	not is_array(resourceType)
	not common_lib.valid_key(resourceType, "description")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_security_group[{{%s}}].%s description is undefined or null", [name, types[y]]), "keyExpectedValue": sprintf("aws_security_group[{{%s}}].%s description should be defined and not null", [name, types[y]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[{{%s}}].%s", [name, types[y]]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, types[y]], [])}
}

security_group_rules_without_description_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	types := {"egress", "ingress"}
	resourceType := resource[types[y]]
	is_array(resourceType)
	currentResource := resourceType[resourceIndex]
	not common_lib.valid_key(currentResource, "description")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_security_group[{{%s}}].%s description is undefined or null", [name, types[y]]), "keyExpectedValue": sprintf("aws_security_group[{{%s}}].%s description should be defined and not null", [name, types[y]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[{{%s}}].%s", [name, types[y]]), "searchLine": common_lib.build_search_line(["resource", "aws_security_group", name, types[y], resourceIndex], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Security Group Rule Without Description"
# description: >-
#   It's considered a best practice for all rules in AWS Security Group to have a description
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.security_group_rules_without_description"
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
#       identifier: aws_security_group
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
security_group_rules_without_description_snippet[violation] {
	security_group_rules_without_description_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

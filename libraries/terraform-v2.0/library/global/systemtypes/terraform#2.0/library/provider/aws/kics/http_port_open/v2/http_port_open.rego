package global.systemtypes["terraform:2.0"].library.provider.aws.kics.http_port_open.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as terraLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

http_port_open_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	terraLib.portOpenToInternet(resource.ingress, 80)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_security_group.ingress opens the HTTP port (80)", "keyExpectedValue": "aws_security_group.ingress shouldn't open the HTTP port (80)", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: HTTP Port Open To Internet"
# description: >-
#   The HTTP port is open to the internet in a Security Group
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.http_port_open"
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
http_port_open_snippet[violation] {
	http_port_open_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sql_analysis_services_port_2383_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sql_analysis_services_port_2383_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.aws_security_group[name]
	tf_lib.portOpenToInternet(resource.ingress, 2383)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_security_group opens SQL Analysis Services Port 2383", "keyExpectedValue": "aws_security_group shouldn't open SQL Analysis Services Port 2383", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_security_group", "searchKey": sprintf("aws_security_group[%s].ingress", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQL Analysis Services Port 2383 (TCP) Is Publicly Accessible"
# description: >-
#   Check if port 2383 on TCP is publicly accessible by checking the CIDR block range that can access it.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sql_analysis_services_port_2383_is_publicly_accessible"
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
sql_analysis_services_port_2383_is_publicly_accessible_snippet[violation] {
	sql_analysis_services_port_2383_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

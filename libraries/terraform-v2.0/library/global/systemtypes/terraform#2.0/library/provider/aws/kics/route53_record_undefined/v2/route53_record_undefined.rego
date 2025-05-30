package global.systemtypes["terraform:2.0"].library.provider.aws.kics.route53_record_undefined.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

route53_record_undefined_inner[result] {
	route := input.document[i].resource.aws_route53_record[name]
	count(route.records) == 0
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_route53_record.records is undefined", "keyExpectedValue": "aws_route53_record.records should be defined", "resourceName": tf_lib.get_resource_name(route, name), "resourceType": "aws_route53_record", "searchKey": sprintf("aws_route53_record[%s].records", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Route53 Record Undefined"
# description: >-
#   Check if Record is set
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.route53_record_undefined"
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
#       identifier: aws_route53_record
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
route53_record_undefined_snippet[violation] {
	route53_record_undefined_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

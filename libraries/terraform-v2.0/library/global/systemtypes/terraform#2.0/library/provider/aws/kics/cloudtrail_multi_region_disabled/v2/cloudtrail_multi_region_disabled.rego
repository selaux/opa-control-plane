package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudtrail_multi_region_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudtrail_multi_region_disabled_inner[result] {
	doc := input.document[i]
	cloudtrail := doc.resource.aws_cloudtrail[name]
	not common_lib.valid_key(cloudtrail, "is_multi_region_trail")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_cloudtrail[%s].is_multi_region_trail is undefined or null", [name]), "keyExpectedValue": sprintf("aws_cloudtrail[%s].is_multi_region_trail should be defined and not null", [name]), "remediation": "is_multi_region_trail = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(cloudtrail, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudtrail", name], [])}
}

cloudtrail_multi_region_disabled_inner[result] {
	doc := input.document[i]
	cloudtrail := doc.resource.aws_cloudtrail[name]
	cloudtrail.is_multi_region_trail == false
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_cloudtrail[%s].is_multi_region_trail is set to false", [name]), "keyExpectedValue": sprintf("aws_cloudtrail[%s].is_multi_region_trail should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cloudtrail, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s].is_multi_region_trail", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudtrail", name, "is_multi_region_trail"], [])}
}

cloudtrail_multi_region_disabled_inner[result] {
	doc := input.document[i]
	cloudtrail := doc.resource.aws_cloudtrail[name]
	cloudtrail.include_global_service_events == false
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_cloudtrail[%s].include_global_service_events is set to false", [name]), "keyExpectedValue": sprintf("aws_cloudtrail[%s].include_global_service_events should be undefined or set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cloudtrail, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s].include_global_service_events", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudtrail", name, "include_global_service_events"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudTrail Multi Region Disabled"
# description: >-
#   CloudTrail multi region should be enabled, which means attributes 'is_multi_region_trail' and 'include_global_service_events' should be enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudtrail_multi_region_disabled"
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
#       identifier: aws_cloudtrail
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
cloudtrail_multi_region_disabled_snippet[violation] {
	cloudtrail_multi_region_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

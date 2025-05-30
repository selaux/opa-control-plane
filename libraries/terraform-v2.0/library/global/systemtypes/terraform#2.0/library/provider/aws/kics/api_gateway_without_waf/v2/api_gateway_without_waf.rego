package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_without_waf.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_without_waf_inner[result] {
	apiGateway := input.document[i].resource.aws_api_gateway_stage[name]
	not has_waf_associated(name)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "API Gateway Stage is not associated with a Web Application Firewall", "keyExpectedValue": "API Gateway Stage should be associated with a Web Application Firewall", "resourceName": tf_lib.get_resource_name(apiGateway, name), "resourceType": "aws_api_gateway_stage", "searchKey": sprintf("aws_api_gateway_stage[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_stage", name], [])}
}

has_waf_associated(apiGatewayName) {
	targetResources := {"aws_wafregional_web_acl_association", "aws_wafv2_web_acl_association"}

	waf := targetResources[_]

	resource := input.document[_].resource[waf][_]

	associatedResource := split(resource.resource_arn, ".")

	associatedResource[0] == "${aws_api_gateway_stage"
	associatedResource[1] == apiGatewayName
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway without WAF"
# description: >-
#   API Gateway should have WAF (Web Application Firewall) enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_without_waf"
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
#       identifier: aws_api_gateway_stage
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
api_gateway_without_waf_snippet[violation] {
	api_gateway_without_waf_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

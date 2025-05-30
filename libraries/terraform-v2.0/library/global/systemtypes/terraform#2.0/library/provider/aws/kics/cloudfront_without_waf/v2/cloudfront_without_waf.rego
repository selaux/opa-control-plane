package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudfront_without_waf.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudfront_without_waf_inner[result] {
	resource := input.document[i].resource.aws_cloudfront_distribution[name]
	resource.enabled == true
	not resource.web_acl_id
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'web_acl_id' is missing", "keyExpectedValue": "'web_acl_id'  should exist", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("aws_cloudfront_distribution[%s].web_acl_id", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudFront Without WAF"
# description: >-
#   All AWS CloudFront distributions should be integrated with the Web Application Firewall (AWS WAF) service
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudfront_without_waf"
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
#       identifier: aws_cloudfront_distribution
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
cloudfront_without_waf_snippet[violation] {
	cloudfront_without_waf_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

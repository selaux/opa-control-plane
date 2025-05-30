package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudfront_viewer_protocol_policy_allows_http.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudfront_viewer_protocol_policy_allows_http_inner[result] {
	resource := input.document[i].resource.aws_cloudfront_distribution[name]
	path := check_allow_all(resource.default_cache_behavior)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].default_cache_behavior.viewer_protocol_policy isn't 'https-only' or 'redirect-to-https'", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].default_cache_behavior.viewer_protocol_policy should be 'https-only' or 'redirect-to-https'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s].default_cache_behavior.viewer_protocol_policy", [name])}
}

cloudfront_viewer_protocol_policy_allows_http_inner[result] {
	resource := input.document[i].resource.aws_cloudfront_distribution[name]
	path = check_allow_all(resource.ordered_cache_behavior)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].ordered_cache_behavior.viewer_protocol_policy isn't 'https-only' or 'redirect-to-https'", [name]), "keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].ordered_cache_behavior.viewer_protocol_policy should be 'https-only' or 'redirect-to-https'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudfront_distribution", "searchKey": sprintf("resource.aws_cloudfront_distribution[%s].ordered_cache_behavior.{{%s}}.viewer_protocol_policy", [name, path[_].path_pattern])}
}

check_allow_all(resource) = path {
	is_array(resource)
	path := {x | resource[n].viewer_protocol_policy == "allow-all"; x := resource[n]}
} else = path {
	not is_array(resource)
	resource.viewer_protocol_policy == "allow-all"
	path := {x | x := resource}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cloudfront Viewer Protocol Policy Allows HTTP"
# description: >-
#   Checks if the connection between CloudFront and the viewer is encrypted
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudfront_viewer_protocol_policy_allows_http"
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
cloudfront_viewer_protocol_policy_allows_http_snippet[violation] {
	cloudfront_viewer_protocol_policy_allows_http_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

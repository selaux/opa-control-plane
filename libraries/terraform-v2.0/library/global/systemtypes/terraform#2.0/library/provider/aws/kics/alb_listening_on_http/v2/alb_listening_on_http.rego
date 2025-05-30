package global.systemtypes["terraform:2.0"].library.provider.aws.kics.alb_listening_on_http.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

alb_listening_on_http_inner[result] {
	resource := input.document[i].resource[lb[idx]][name]
	check_application(resource)
	is_http(resource)
	not common_lib.valid_key(resource.default_action, "redirect")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'default_action.redirect' is missing", "keyExpectedValue": "'default_action.redirect.protocol' should be equal to 'HTTPS'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": lb[idx], "searchKey": sprintf("%s[%s].default_action", [lb[idx], name]), "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "default_action"], [])}
}

alb_listening_on_http_inner[result] {
	resource := input.document[i].resource[lb[idx]][name]
	check_application(resource)
	is_http(resource)
	not common_lib.valid_key(resource.default_action.redirect, "protocol")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'default_action.redirect.protocol' is missing", "keyExpectedValue": "'default_action.redirect.protocol' should be equal to 'HTTPS'", "remediation": "protocol = \"HTTPS\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": lb[idx], "searchKey": sprintf("%s[%s].default_action.redirect", [lb[idx], name]), "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "default_action", "redirect"], [])}
}

alb_listening_on_http_inner[result] {
	resource := input.document[i].resource[lb[idx]][name]
	check_application(resource)
	is_http(resource)
	upper(resource.default_action.redirect.protocol) != "HTTPS"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'default_action.redirect.protocol' is equal '%s'", [resource.default_action.redirect.protocol]), "keyExpectedValue": "'default_action.redirect.protocol' should be equal to 'HTTPS'", "remediation": json.marshal({"after": "HTTPS", "before": sprintf("%s", [resource.default_action.redirect.protocol])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": lb[idx], "searchKey": sprintf("%s[%s].default_action.redirect.protocol", [lb[idx], name]), "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "default_action", "redirect", "protocol"], [])}
}

is_http(resource) {
	upper(resource.protocol) == "HTTP"
}

is_http(resource) {
	not common_lib.valid_key(resource, "protocol")
}

is_application(resource) {
	resource.load_balancer_type == "application"
}

is_application(resource) {
	not common_lib.valid_key(resource, "load_balancer_type")
}

check_application(resource) {
	lbs := {"aws_alb", "aws_lb"}
	lb_info := split(resource.load_balancer_arn, ".")
	lb_name = lb_info[1]
	lb := input.document[_].resource[lbs[idx]][name]
	lb_name == name
	is_application(lb)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ALB Listening on HTTP"
# description: >-
#   AWS Application Load Balancer (alb) should not listen on HTTP
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.alb_listening_on_http"
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
#       identifier: aws_lb_listener
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
alb_listening_on_http_snippet[violation] {
	alb_listening_on_http_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

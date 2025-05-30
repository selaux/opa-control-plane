package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sso_permission_with_inadequate_user_session_duration.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sso_permission_with_inadequate_user_session_duration_inner[result] {
	resource := input.document[i].resource.aws_ssoadmin_permission_set[name]
	session_duration := resource.session_duration
	more_than_one_hour(session_duration)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "session_duration is higher than 1 hour", "keyExpectedValue": "session_duration should not be higher than 1 hour", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ssoadmin_permission_set_inline_policy", "searchKey": sprintf("aws_ssoadmin_permission_set[%s].session_duration", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ssoadmin_permission_set_inline_policy", name, "session_duration"], [])}
}

more_than_one_hour(session_duration) {
	time := (get_hours_value(session_duration) + get_minutes_value(session_duration)) + get_seconds_value(session_duration)
	time > 3600
}

get_hours_value(session_duration) := duration {
	hours_value := trim_suffix(regex.find_all_string_submatch_n(`\d{1,2}H`, session_duration, 1)[0][0], "H")
	duration := 3600 * to_number(hours_value)
} else := 0

get_minutes_value(session_duration) := duration {
	minutes_value := trim_suffix(regex.find_all_string_submatch_n(`\d{1,2}M`, session_duration, 1)[0][0], "M")
	duration := 60 * to_number(minutes_value)
} else := 0

get_seconds_value(session_duration) := duration {
	seconds_value := trim_suffix(regex.find_all_string_submatch_n(`\d{1,2}S`, session_duration, 1)[0][0], "S")
	duration := to_number(seconds_value)
} else := 0

# METADATA: library-snippet
# version: v1
# title: "KICS: SSO Permission With Inadequate User Session Duration"
# description: >-
#   SSO permissions should be configured to limit user sessions to no longer than 1 hour. Allowing longer sessions can increase the risk of unauthorized access or session hijacking. This is a best practice for security and should be implemented in SSO permission settings.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sso_permission_with_inadequate_user_session_duration"
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
#       identifier: aws_ssoadmin_permission_set_inline_policy
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
sso_permission_with_inadequate_user_session_duration_snippet[violation] {
	sso_permission_with_inadequate_user_session_duration_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

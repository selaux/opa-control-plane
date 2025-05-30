package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_policy_accepts_http_requests.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

resources := {"aws_s3_bucket_policy", "aws_s3_bucket"}

s3_bucket_policy_accepts_http_requests_inner[result] {
	resourceType := resources[r]
	resource := input.document[i].resource[resourceType][name]
	policy_unmarshaled := common_lib.json_unmarshal(resource.policy)
	not deny_http_requests(policy_unmarshaled)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].policy accepts HTTP Requests", [resourceType, name]), "keyExpectedValue": sprintf("%s[%s].policy should not accept HTTP Requests", [resourceType, name]), "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].policy", [resourceType, name]), "searchLine": common_lib.build_search_line(["resource", resourceType, name, "policy"], [])}
}

s3_bucket_policy_accepts_http_requests_inner[result] {
	module := input.document[i].module[name]
	resourceType := resources[r]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, resourceType, "policy")
	policy := module[keyToCheck]
	policy_unmarshaled := common_lib.json_unmarshal(policy)
	not deny_http_requests(policy_unmarshaled)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy' accepts HTTP Requests", "keyExpectedValue": "'policy' should not accept HTTP Requests", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].policy", [name]), "searchLine": common_lib.build_search_line(["module", name, "policy"], [])}
}

any_s3_action(action) {
	any([action == "*", startswith(action, "s3:")])
}

check_action(st) {
	is_string(st.Action)
	any_s3_action(st.Action)
} else {
	any_s3_action(st.Action[a])
} else {
	is_string(st.Actions)
	any_s3_action(st.Actions)
} else {
	any_s3_action(st.Actions[a])
}

is_equal(secure, target) {
	secure == target
} else {
	secure[_] == target
}

deny_http_requests(policyValue) {
	st := common_lib.get_statement(policyValue)
	statement := st[_]
	check_action(statement)
	statement.Effect == "Deny"
	is_equal(statement.Condition.Bool["aws:SecureTransport"], "false")
} else {
	st := common_lib.get_statement(policyValue)
	statement := st[_]
	check_action(statement)
	statement.Effect == "Allow"
	is_equal(statement.Condition.Bool["aws:SecureTransport"], "true")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Policy Accepts HTTP Requests"
# description: >-
#   S3 Bucket policy should not accept HTTP Requests
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_policy_accepts_http_requests"
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
s3_bucket_policy_accepts_http_requests_snippet[violation] {
	s3_bucket_policy_accepts_http_requests_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_with_all_permissions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

resource_type := {"aws_s3_bucket_policy", "aws_s3_bucket"}

s3_bucket_with_all_permissions_inner[result] {
	res_type := resource_type[_0]
	resource := input.document[i].resource[res_type][name]
	all_permissions(resource.policy)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement' allows all actions to all principal", "keyExpectedValue": "'policy.Statement' should not allow all actions to all principal", "resourceName": tf_lib.get_specific_resource_name(resource, res_type, name), "resourceType": res_type, "searchKey": sprintf("%s[%s].policy", [res_type, name]), "searchLine": common_lib.build_search_line(["resource", res_type, name, "policy"], [])}
}

s3_bucket_with_all_permissions_inner[result] {
	module := input.document[i].module[name]
	res_type := resource_type[_0]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, res_type, "policy")
	all_permissions(module[keyToCheck])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement' allows all actions to all principal", "keyExpectedValue": "'policy.Statement' should not allow all actions to all principal", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].policy", [name]), "searchLine": common_lib.build_search_line(["module", name, "policy"], [])}
}

all_permissions(policyValue) {
	policy := common_lib.json_unmarshal(policyValue)
	st := common_lib.get_statement(policy)
	statement := st[_]

	common_lib.is_allow_effect(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")
	common_lib.containsOrInArrayContains(statement.Principal, "*")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket With All Permissions"
# description: >-
#   S3 Buckets should not have all permissions, as to prevent leaking private information to the entire internet or allow unauthorized data tampering / deletion. This means the 'Effect' must not be 'Allow' when the 'Action' is '*', for all Principals.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_with_all_permissions"
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
s3_bucket_with_all_permissions_snippet[violation] {
	s3_bucket_with_all_permissions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

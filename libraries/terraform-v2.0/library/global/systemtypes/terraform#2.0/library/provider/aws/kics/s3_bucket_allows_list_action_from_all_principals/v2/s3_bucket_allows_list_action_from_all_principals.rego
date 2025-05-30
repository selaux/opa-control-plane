package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_allows_list_action_from_all_principals.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

pl := {"aws_s3_bucket_policy", "aws_s3_bucket"}

s3_bucket_allows_list_action_from_all_principals_inner[result] {
	resourceType := pl[r]
	resource := input.document[i].resource[resourceType][name]
	tf_lib.allows_action_from_all_principals(resource.policy, "list")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Action' is a 'List' action when 'policy.Statement.Principal' contains '*'", "keyExpectedValue": "'policy.Statement.Action' should not be a 'List' action when 'policy.Statement.Principal' contains '*'", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].policy", [resourceType, name]), "searchLine": common_lib.build_search_line(["resource", resourceType, name, "policy"], [])}
}

s3_bucket_allows_list_action_from_all_principals_inner[result] {
	module := input.document[i].module[name]
	resourceValue := pl[r]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, resourceValue, "policy")
	tf_lib.allows_action_from_all_principals(module[keyToCheck], "list")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Action' is a 'List' action when 'policy.Statement.Principal' contains '*'", "keyExpectedValue": "'policy.Statement.Action' should not be a 'List' action when 'policy.Statement.Principal' contains '*'", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].policy", [name]), "searchLine": common_lib.build_search_line(["module", name, "policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Allows List Action From All Principals"
# description: >-
#   S3 Buckets must not allow List Action From All Principals, as to prevent leaking private information to the entire internet or allow unauthorized data tampering / deletion. This means the 'Effect' must not be 'Allow' when the 'Action' is List, for all Principals.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_allows_list_action_from_all_principals"
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
#       identifier: aws_s3_bucket_policy
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
s3_bucket_allows_list_action_from_all_principals_snippet[violation] {
	s3_bucket_allows_list_action_from_all_principals_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

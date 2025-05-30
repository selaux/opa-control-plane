package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_acl_grants_write_acp_permission.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

s3_bucket_acl_grants_write_acp_permission_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket_acl[name]
	acl_policy := resource.access_control_policy
	is_array(acl_policy.grant)
	grant := acl_policy.grant[grant_index]
	grant.permission == "WRITE_ACP"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Write_ACP permission is granted to the aws_s3_bucket_acl", "keyExpectedValue": "Should not be granted Write_ACP permission to the aws_s3_bucket_acl", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket_acl", name), "resourceType": "aws_s3_bucket_acl", "searchKey": sprintf("aws_s3_bucket_acl[%s].access_control_policy.grant[%d].permission", [name, grant_index]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_acl", name, "access_control_policy", "grant", grant_index, "permission"], [])}
}

s3_bucket_acl_grants_write_acp_permission_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket_acl[name]
	acl_policy := resource.access_control_policy
	not is_array(acl_policy.grant)
	grant := acl_policy.grant
	grant.permission == "WRITE_ACP"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Write_ACP permission is granted to the aws_s3_bucket_acl", "keyExpectedValue": "Should not be granted Write_ACP permission to the aws_s3_bucket_acl", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket_acl", name), "resourceType": "aws_s3_bucket_acl", "searchKey": sprintf("aws_s3_bucket_acl[%s].access_control_policy.grant.permission", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_acl", name, "access_control_policy", "grant", "permission"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket ACL Grants WRITE_ACP Permission"
# description: >-
#   S3 Buckets should not allow WRITE_ACP permission to the S3 Bucket Access Control List in order to prevent AWS accounts or IAM users to modify access control permissions to the bucket.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_acl_grants_write_acp_permission"
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
#       identifier: aws_s3_bucket_acl
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
s3_bucket_acl_grants_write_acp_permission_snippet[violation] {
	s3_bucket_acl_grants_write_acp_permission_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

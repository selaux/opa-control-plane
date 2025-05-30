package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_acl_allows_read_or_write_to_all_users.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

# version before TF AWS 4.0
s3_bucket_acl_allows_read_or_write_to_all_users_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket[name]
	publicAccessACL(resource.acl)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'acl' is equal '%s'", [resource.acl]), "keyExpectedValue": "'acl' should equal to 'private'", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].acl=%s", [name, resource.acl]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "acl"], [])}
}

s3_bucket_acl_allows_read_or_write_to_all_users_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "acl")
	publicAccessACL(module[keyToCheck])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'acl' is equal '%s'", [module[keyToCheck]]), "keyExpectedValue": "'acl' should equal to 'private'", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].acl", [name]), "searchLine": common_lib.build_search_line(["module", name, "acl"], [])}
}

# version after TF AWS 4.0
s3_bucket_acl_allows_read_or_write_to_all_users_inner[result] {
	input.document[_].resource.aws_s3_bucket[bucketName]
	acl := input.document[i].resource.aws_s3_bucket_acl[name]
	split(acl.bucket, ".")[1] == bucketName
	publicAccessACL(acl.acl)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_s3_bucket_acl[%s].acl is %s", [acl.acl]), "keyExpectedValue": sprintf("aws_s3_bucket_acl[%s].acl should be private", [name]), "resourceName": tf_lib.get_resource_name(acl, name), "resourceType": "aws_s3_bucket_acl", "searchKey": sprintf("aws_s3_bucket_acl[%s].acl", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_acl", name, "acl"], [])}
}

publicAccessACL("public-read") = true

publicAccessACL("public-read-write") = true

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket ACL Allows Read Or Write to All Users"
# description: >-
#   S3 Buckets should not be readable and writable to all users
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_acl_allows_read_or_write_to_all_users"
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
s3_bucket_acl_allows_read_or_write_to_all_users_snippet[violation] {
	s3_bucket_acl_allows_read_or_write_to_all_users_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_public_acl_overridden_by_public_access_block.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

s3_bucket_public_acl_overridden_by_public_access_block_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket[name]
	publicAccessACL(resource.acl)
	publicBlockACL := input.document[_0].resource.aws_s3_bucket_public_access_block[blockName]
	split(publicBlockACL.bucket, ".")[1] == name
	public(publicBlockACL)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "S3 Bucket public ACL is overridden by S3 bucket Public Access Block", "keyExpectedValue": "S3 Bucket public ACL to not be overridden by S3 bucket Public Access Block", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].acl", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "acl"], [])}
	# version before TF AWS 4.0

	# version after TF AWS 4.0

}

s3_bucket_public_acl_overridden_by_public_access_block_inner[result] {
	module := input.document[i].module[name]
	keyToCheckAcl := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket_public_access_block", "acl")
	publicAccessACL(module[keyToCheckAcl])
	options = {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
	count({x | keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket_public_access_block", options[x]); module[keyToCheck] == true}) == 4
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "S3 Bucket public ACL is overridden by public access block", "keyExpectedValue": "S3 Bucket public ACL to not be overridden by public access block", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].acl", [name]), "searchLine": common_lib.build_search_line(["module", name, "acl"], [])}
}

s3_bucket_public_acl_overridden_by_public_access_block_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	acl := input.document[i].resource.aws_s3_bucket_acl[name]
	split(acl.bucket, ".")[1] == bucketName
	publicAccessACL(acl.acl)
	publicBlockACL := input.document[_].resource.aws_s3_bucket_public_access_block[blockName]
	split(publicBlockACL.bucket, ".")[1] == bucketName
	public(publicBlockACL)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "S3 Bucket public ACL is overridden by S3 bucket Public Access Block", "keyExpectedValue": "S3 Bucket public ACL to not be overridden by S3 bucket Public Access Block", "resourceName": tf_lib.get_resource_name(acl, name), "resourceType": "aws_s3_bucket_acl", "searchKey": sprintf("aws_s3_bucket_acl[%s].acl", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_acl", name, "acl"], [])}
	# version before TF AWS 4.0

	# version after TF AWS 4.0

}

publicAccessACL("public-read") = true

publicAccessACL("public-read-write") = true

public(publicBlockACL) {
	publicBlockACL.block_public_acls == true
	publicBlockACL.block_public_policy == true
	publicBlockACL.ignore_public_acls == true
	publicBlockACL.restrict_public_buckets == true
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Public ACL Overridden By Public Access Block"
# description: >-
#   S3 bucket public access is overridden by S3 bucket Public Access Block when the following attributes are set to true - 'block_public_acls', 'block_public_policy', 'ignore_public_acls', and 'restrict_public_buckets'
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_public_acl_overridden_by_public_access_block"
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
s3_bucket_public_acl_overridden_by_public_access_block_snippet[violation] {
	s3_bucket_public_acl_overridden_by_public_access_block_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

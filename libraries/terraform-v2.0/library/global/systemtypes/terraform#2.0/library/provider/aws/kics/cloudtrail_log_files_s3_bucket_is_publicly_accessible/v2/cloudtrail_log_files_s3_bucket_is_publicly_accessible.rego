package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudtrail_log_files_s3_bucket_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

publicAcl := {"public-read", "public-read-write"}

# version before TF AWS 4.0
cloudtrail_log_files_s3_bucket_is_publicly_accessible_inner[result] {
	cloudtrail := input.document[_0].resource.aws_cloudtrail[name]
	s3BucketName := split(cloudtrail.s3_bucket_name, ".")[1]
	bucket := input.document[i].resource.aws_s3_bucket[s3BucketName]
	bucket.acl == publicAcl[_1]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_s3_bucket[%s] is publicly accessible", [s3BucketName]), "keyExpectedValue": sprintf("aws_s3_bucket[%s] to not be publicly accessible", [s3BucketName]), "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", s3BucketName), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].acl", [s3BucketName])}
}

cloudtrail_log_files_s3_bucket_is_publicly_accessible_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "acl")
	module[keyToCheck] == publicAcl[_0]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("module[%s] is publicly accessible", [name]), "keyExpectedValue": sprintf("module[%s] to not be publicly accessible", [name]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].acl", [name])}
}

# version after TF AWS 4.0
cloudtrail_log_files_s3_bucket_is_publicly_accessible_inner[result] {
	cloudtrail := input.document[_0].resource.aws_cloudtrail[name]
	s3BucketName := split(cloudtrail.s3_bucket_name, ".")[1]
	input.document[_1].resource.aws_s3_bucket[s3BucketName]
	acl := input.document[i].resource.aws_s3_bucket_acl[name]
	split(acl.bucket, ".")[1] == s3BucketName
	acl.acl == publicAcl[_]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_s3_bucket_acl[%s] is publicly accessible", [name]), "keyExpectedValue": sprintf("aws_s3_bucket_acl[%s] to not be publicly accessible", [name]), "resourceName": tf_lib.get_resource_name(acl, name), "resourceType": "aws_s3_bucket_acl", "searchKey": sprintf("aws_s3_bucket_acl[%s].acl", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudTrail Log Files S3 Bucket is Publicly Accessible"
# description: >-
#   CloudTrail Log Files S3 Bucket should not be publicly accessible
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudtrail_log_files_s3_bucket_is_publicly_accessible"
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
cloudtrail_log_files_s3_bucket_is_publicly_accessible_snippet[violation] {
	cloudtrail_log_files_s3_bucket_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

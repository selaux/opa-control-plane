package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudtrail_log_files_s3_bucket_with_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudtrail_log_files_s3_bucket_with_logging_disabled_inner[result] {
	cloudtrail := input.document[_0].resource.aws_cloudtrail[name]
	s3BucketName := split(cloudtrail.s3_bucket_name, ".")[1]
	bucket := input.document[i].resource.aws_s3_bucket[s3BucketName]
	not common_lib.valid_key(bucket, "logging")
	not tf_lib.has_target_resource(s3BucketName, "aws_s3_bucket_logging")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_s3_bucket[%s] does not have 'logging' defined", [s3BucketName]), "keyExpectedValue": sprintf("aws_s3_bucket[%s] to have 'logging' defined", [s3BucketName]), "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", s3BucketName), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s]", [s3BucketName]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", s3BucketName], [])}
	# version before TF AWS 4.0
	# version after TF AWS 4.0

}

cloudtrail_log_files_s3_bucket_with_logging_disabled_inner[result] {
	logs := input.document[_0].resource.aws_cloudtrail[name]
	s3BucketName := split(logs.s3_bucket_name, ".")[1]
	doc := input.document[i].module[moduleName]
	keyToCheck := common_lib.get_module_equivalent_key("aws", doc.source, "aws_s3_bucket", "logging")
	doc.bucket == s3BucketName
	not common_lib.valid_key(doc, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'logging' is undefined", "keyExpectedValue": "'logging' should be defined", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [moduleName]), "searchLine": common_lib.build_search_line(["module", moduleName], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudTrail Log Files S3 Bucket with Logging Disabled"
# description: >-
#   CloudTrail Log Files S3 Bucket should have 'logging' enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudtrail_log_files_s3_bucket_with_logging_disabled"
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
cloudtrail_log_files_s3_bucket_with_logging_disabled_snippet[violation] {
	cloudtrail_log_files_s3_bucket_with_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

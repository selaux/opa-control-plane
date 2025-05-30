package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

s3_bucket_logging_disabled_inner[result] {
	s3 := input.document[i].resource.aws_s3_bucket[bucketName]
	not common_lib.valid_key(s3, "logging")
	not tf_lib.has_target_resource(bucketName, "aws_s3_bucket_logging")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'logging' is undefined or null", "keyExpectedValue": "'logging' should be defined and not null", "resourceName": tf_lib.get_specific_resource_name(s3, "aws_s3_bucket", bucketName), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s]", [bucketName]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", bucketName], [])}
	# version before TF AWS 4.0
	# version after TF AWS 4.0

}

s3_bucket_logging_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "logging")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'logging' is undefined or null", "keyExpectedValue": "'logging' should be defined and not null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Logging Disabled"
# description: >-
#   Server Access Logging should be enabled on S3 Buckets so that all changes are logged and trackable
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_logging_disabled"
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
s3_bucket_logging_disabled_snippet[violation] {
	s3_bucket_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

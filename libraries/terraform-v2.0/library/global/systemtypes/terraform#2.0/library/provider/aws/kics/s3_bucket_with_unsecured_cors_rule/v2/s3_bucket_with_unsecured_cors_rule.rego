package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_with_unsecured_cors_rule.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

# version before TF AWS 4.0
s3_bucket_with_unsecured_cors_rule_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	rule := bucket.cors_rule
	common_lib.unsecured_cors_rule(rule.allowed_methods, rule.allowed_headers, rule.allowed_origins)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'cors_rule' allows all methods, all headers or several origins", "keyExpectedValue": "'cors_rule' to not allow all methods, all headers or several origins", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].cors_rule", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "cors_rule"], [])}
}

# version before TF AWS 4.0
s3_bucket_with_unsecured_cors_rule_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	rule := bucket.cors_rule[idx]
	common_lib.unsecured_cors_rule(rule.allowed_methods, rule.allowed_headers, rule.allowed_origins)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'cors_rule' allows all methods, all headers or several origins", "keyExpectedValue": "'cors_rule' to not allow all methods, all headers or several origins", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].cors_rule", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "cors_rule", idx], [])}
}

s3_bucket_with_unsecured_cors_rule_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "cors_rule")
	rule := module.cors_rule[ruleIdx]
	common_lib.unsecured_cors_rule(rule.allowed_methods, rule.allowed_headers, rule.allowed_origins)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'cors_rule' allows all methods, all headers or several origins", "keyExpectedValue": "'cors_rule' to not allow all methods, all headers or several origins", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].cors_rule", [name]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck, ruleIdx], [])}
}

# version after TF AWS 4.0
s3_bucket_with_unsecured_cors_rule_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	cors_configuration := input.document[i].resource.aws_s3_bucket_cors_configuration[name]
	split(cors_configuration.bucket, ".")[1] == bucketName
	rule := cors_configuration.cors_rule
	common_lib.unsecured_cors_rule(rule.allowed_methods, rule.allowed_headers, rule.allowed_origins)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'cors_rule' allows all methods, all headers or several origins", "keyExpectedValue": "'cors_rule' to not allow all methods, all headers or several origins", "resourceName": tf_lib.get_resource_name(cors_configuration, name), "resourceType": "aws_s3_bucket_cors_configuration", "searchKey": sprintf("aws_s3_bucket_cors_configuration[%s].cors_rule", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_cors_configuration", name, "cors_rule"], [])}
}

# version after TF AWS 4.0
s3_bucket_with_unsecured_cors_rule_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	cors_configuration := input.document[i].resource.aws_s3_bucket_cors_configuration[name]
	split(cors_configuration.bucket, ".")[1] == bucketName
	rule := cors_configuration.cors_rule[idx]
	common_lib.unsecured_cors_rule(rule.allowed_methods, rule.allowed_headers, rule.allowed_origins)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'cors_rule' allows all methods, all headers or several origins", "keyExpectedValue": "'cors_rule' to not allow all methods, all headers or several origins", "resourceName": tf_lib.get_resource_name(cors_configuration, name), "resourceType": "aws_s3_bucket_cors_configuration", "searchKey": sprintf("aws_s3_bucket_cors_configuration[%s].cors_rule", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_cors_configuration", name, "cors_rule", idx], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket with Unsecured CORS Rule"
# description: >-
#   If the CORS (Cross-Origin Resource Sharing) rule is defined in an S3 bucket, it should be secure
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_with_unsecured_cors_rule"
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
#       identifier: aws_s3_bucket
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_s3_bucket_cors_configuration
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
s3_bucket_with_unsecured_cors_rule_snippet[violation] {
	s3_bucket_with_unsecured_cors_rule_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

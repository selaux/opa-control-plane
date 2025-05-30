package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_static_website_host_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

# version before TF AWS 4.0
s3_static_website_host_enabled_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket[name]
	count(resource.website) > 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_s3_bucket[%s].website does have static websites inside", [name]), "keyExpectedValue": sprintf("resource.aws_s3_bucket[%s].website to not have static websites inside", [name]), "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("resource.aws_s3_bucket[%s].website", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "website"], [])}
}

s3_static_website_host_enabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "website")
	count(module[keyToCheck]) > 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'website' does have static websites inside", "keyExpectedValue": "'website' to not have static websites inside", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].website", [name]), "searchLine": common_lib.build_search_line(["module", name, "website"], [])}
}

# version after TF AWS 4.0
s3_static_website_host_enabled_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket[bucketName]
	tf_lib.has_target_resource(bucketName, "aws_s3_bucket_website_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'aws_s3_bucket' has 'aws_s3_bucket_website_configuration' associated", "keyExpectedValue": "'aws_s3_bucket' to not have 'aws_s3_bucket_website_configuration' associated", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", bucketName), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s]", [bucketName]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", bucketName], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Static Website Host Enabled"
# description: >-
#   Checks if any static websites are hosted on buckets. Even static websites can be a liability when poorly configured.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_static_website_host_enabled"
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
s3_static_website_host_enabled_snippet[violation] {
	s3_static_website_host_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

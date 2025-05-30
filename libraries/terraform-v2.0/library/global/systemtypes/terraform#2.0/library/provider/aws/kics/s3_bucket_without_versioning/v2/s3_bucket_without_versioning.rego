package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_without_versioning.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

#default of versioning is false
s3_bucket_without_versioning_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[bucketName]
	not common_lib.valid_key(bucket, "versioning")
	not tf_lib.has_target_resource(bucketName, "aws_s3_bucket_versioning")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'versioning' is undefined or null", "keyExpectedValue": "'versioning' should be true", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", bucketName), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s]", [bucketName]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", bucketName], [])}
	# version before TF AWS 4.0
	# version after TF AWS 4.0

}

s3_bucket_without_versioning_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "versioning")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'versioning' is undefined or null", "keyExpectedValue": "'versioning' should be true", "remediation": sprintf("%s {\n\t\t enabled = true\n\t}", [keyToCheck]), "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

#default of enabled is false
# version before TF AWS 4.0
s3_bucket_without_versioning_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	not common_lib.valid_key(bucket.versioning, "enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'versioning.enabled' is undefined or null", "keyExpectedValue": "'versioning.enabled' should be true", "remediation": "enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].versioning", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "versioning"], [])}
}

s3_bucket_without_versioning_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "versioning")
	not common_lib.valid_key(module[keyToCheck], "enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'versioning.enabled' is undefined or null", "keyExpectedValue": "'versioning.enabled' should be true", "remediation": "enabled = true", "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].versioning", [name]), "searchLine": common_lib.build_search_line(["module", name, "versioning"], [])}
}

# version before TF AWS 4.0
s3_bucket_without_versioning_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.versioning.enabled != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'versioning.enabled' is set to false", "keyExpectedValue": "'versioning.enabled' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].versioning.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "versioning", "enabled"], [])}
}

s3_bucket_without_versioning_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "versioning")
	module[keyToCheck].enabled != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'versioning.enabled' is set to false", "keyExpectedValue": "'versioning.enabled' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].versioning.enabled", [name]), "searchLine": common_lib.build_search_line(["module", name, "versioning", "enabled"], [])}
}

# version after TF AWS 4.0
s3_bucket_without_versioning_inner[result] {
	input.document[_].resource.aws_s3_bucket[bucketName]
	bucket_versioning := input.document[i].resource.aws_s3_bucket_versioning[name]
	split(bucket_versioning.bucket, ".")[1] == bucketName
	bucket_versioning.versioning_configuration.status == "Suspended"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'versioning_configuration.status' is set to 'Suspended'", "keyExpectedValue": "'versioning_configuration.status' should be set to 'Enabled'", "remediation": json.marshal({"after": "Enabled", "before": "Suspended"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(bucket_versioning, name), "resourceType": "aws_s3_bucket_versioning", "searchKey": sprintf("aws_s3_bucket_versioning[%s].versioning_configuration.status", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_versioning", name, "versioning_configuration", "status"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Without Versioning"
# description: >-
#   S3 bucket should have versioning enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_without_versioning"
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
#     - argument: ""
#       identifier: aws_s3_bucket
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_s3_bucket_versioning
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
s3_bucket_without_versioning_snippet[violation] {
	s3_bucket_without_versioning_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

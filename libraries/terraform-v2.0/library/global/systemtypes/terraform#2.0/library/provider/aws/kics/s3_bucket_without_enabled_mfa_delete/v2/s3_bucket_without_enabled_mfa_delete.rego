package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_without_enabled_mfa_delete.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

s3_bucket_without_enabled_mfa_delete_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	not common_lib.valid_key(bucket, "lifecycle_rule")
	not common_lib.valid_key(bucket, "versioning")
	not tf_lib.has_target_resource(name, "aws_s3_bucket_lifecycle_configuration")
	not tf_lib.has_target_resource(name, "aws_s3_bucket_versioning")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "versioning is undefined or null", "keyExpectedValue": "versioning should be defined and not null", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name], [])}
	# version before TF AWS 4.0

	# version after TF AWS 4.0

}

checkedFields = {
	"enabled",
	"mfa_delete",
}

# version before TF AWS 4.0
s3_bucket_without_enabled_mfa_delete_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	not common_lib.valid_key(bucket, "lifecycle_rule")
	not common_lib.valid_key(bucket.versioning, checkedFields[j])
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'%s' is undefined or null", [checkedFields[j]]), "keyExpectedValue": sprintf("'%s' should be set to true", [checkedFields[j]]), "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].versioning", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "versioning"], [])}
}

# version before TF AWS 4.0
s3_bucket_without_enabled_mfa_delete_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	not common_lib.valid_key(bucket, "lifecycle_rule")
	bucket.versioning[checkedFields[j]] != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'%s' is set to false", [checkedFields[j]]), "keyExpectedValue": sprintf("'%s' should be set to true", [checkedFields[j]]), "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].versioning.%s", [name, checkedFields[j]]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "versioning", checkedFields[j]], [])}
}

s3_bucket_without_enabled_mfa_delete_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "versioning")
	not common_lib.valid_key(module, "lifecycle_rule")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'versioning' is undefined or null", "keyExpectedValue": "'versioning' should be defined and not null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

s3_bucket_without_enabled_mfa_delete_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "versioning")
	not common_lib.valid_key(module, "lifecycle_rule")
	not common_lib.valid_key(module[keyToCheck], checkedFields[c])
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'%s' is undefined or null", [checkedFields[c]]), "keyExpectedValue": sprintf("'%s' should be set to true", [checkedFields[c]]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].versioning", [name]), "searchLine": common_lib.build_search_line(["module", name, "versioning"], [])}
}

s3_bucket_without_enabled_mfa_delete_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "versioning")
	not common_lib.valid_key(module, "lifecycle_rule")
	module[keyToCheck][checkedFields[c]] != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'%s' is set to false", [checkedFields[c]]), "keyExpectedValue": sprintf("'%s' should be set to true", [checkedFields[c]]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].versioning.%s", [name, checkedFields[c]]), "searchLine": common_lib.build_search_line(["module", name, "versioning", checkedFields[c]], [])}
}

# version after TF AWS 4.0
s3_bucket_without_enabled_mfa_delete_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	not tf_lib.has_target_resource(bucketName, "aws_s3_bucket_lifecycle_configuration")
	bucket_versioning := input.document[i].resource.aws_s3_bucket_versioning[name]
	split(bucket_versioning.bucket, ".")[1] == bucketName
	bucket_versioning.versioning_configuration.mfa_delete == "Disabled"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'versioning_configuration.mfa_delete' is set to 'Disabled'", "keyExpectedValue": "'versioning_configuration.mfa_delete' should be set to 'Enabled'", "resourceName": tf_lib.get_resource_name(bucket_versioning, name), "resourceType": "aws_s3_bucket_versioning", "searchKey": sprintf("aws_s3_bucket_versioning[%s].versioning_configuration.mfa_delete", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_versioning", name, "versioning_configuration", "mfa_delete"], [])}
}

# version after TF AWS 4.0
s3_bucket_without_enabled_mfa_delete_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	not tf_lib.has_target_resource(bucketName, "aws_s3_bucket_lifecycle_configuration")
	bucket_versioning := input.document[i].resource.aws_s3_bucket_versioning[name]
	split(bucket_versioning.bucket, ".")[1] == bucketName
	bucket_versioning.versioning_configuration.status != "Enabled"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'versioning_configuration.status' is set to 'Disabled'", "keyExpectedValue": "'versioning_configuration.status' should be set to 'Enabled'", "resourceName": tf_lib.get_resource_name(bucket_versioning, name), "resourceType": "aws_s3_bucket_versioning", "searchKey": sprintf("aws_s3_bucket_versioning[%s].versioning_configuration.status", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_versioning", name, "versioning_configuration", "status"], [])}
}

# version after TF AWS 4.0
s3_bucket_without_enabled_mfa_delete_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	not tf_lib.has_target_resource(bucketName, "aws_s3_bucket_lifecycle_configuration")
	bucket_versioning := input.document[i].resource.aws_s3_bucket_versioning[name]
	split(bucket_versioning.bucket, ".")[1] == bucketName
	not common_lib.valid_key(bucket_versioning.versioning_configuration, "mfa_delete")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'versioning_configuration.mfa_delete' is undefined and not null", "keyExpectedValue": "'versioning_configuration.mfa_delete' should be defined and not null", "resourceName": tf_lib.get_resource_name(bucket_versioning, name), "resourceType": "aws_s3_bucket_versioning", "searchKey": sprintf("aws_s3_bucket_versioning[%s].versioning_configuration", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_versioning", name, "versioning_configuration"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Without Enabled MFA Delete"
# description: >-
#   S3 bucket without MFA Delete Enabled. MFA delete cannot be enabled through Terraform, it can be done by adding a MFA device (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html) and enabling versioning and MFA delete by using AWS CLI: 'aws s3api put-bucket-versioning --versioning-configuration=Status=Enabled,MFADelete=Enabled --bucket="BUCKET_NAME" --mfa="MFA_SERIAL_NUMBER"'. Please, also notice that MFA delete can not be used with lifecycle configurations
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_without_enabled_mfa_delete"
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
s3_bucket_without_enabled_mfa_delete_snippet[violation] {
	s3_bucket_without_enabled_mfa_delete_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

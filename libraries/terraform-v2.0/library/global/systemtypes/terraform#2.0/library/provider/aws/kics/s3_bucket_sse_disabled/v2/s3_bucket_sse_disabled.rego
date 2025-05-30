package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_sse_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

# version before TF AWS 4.0
s3_bucket_sse_disabled_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	sse := bucket.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default
	check_master_key(sse)
	sse.sse_algorithm != "AES256"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'sse_algorithm' is %s when key is null", [sse.sse_algorithm]), "keyExpectedValue": "'sse_algorithm' should be AES256 when key is null", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "sse_algorithm"], [])}
}

s3_bucket_sse_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "server_side_encryption_configuration")
	ssec := module[keyToCheck]
	algorithm := ssec.rule.apply_server_side_encryption_by_default
	check_master_key(algorithm)
	algorithm.sse_algorithm != "AES256"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'sse_algorithm' is %s when key is null", [algorithm.sse_algorithm]), "keyExpectedValue": "'sse_algorithm' should be AES256 when key is null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm", [name]), "searchLine": common_lib.build_search_line(["module", name, "server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "sse_algorithm"], [])}
}

# version before TF AWS 4.0
s3_bucket_sse_disabled_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket[name]
	ssec := resource.server_side_encryption_configuration
	algorithm := ssec.rule.apply_server_side_encryption_by_default
	not check_master_key(algorithm)
	algorithm.sse_algorithm == "AES256"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'kms_master_key_id'is not null when algorithm is 'AES256'", "keyExpectedValue": "'kms_master_key_id' should be null when algorithm is 'AES256'", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s].server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.kms_master_key_id", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "kms_master_key_id"], [])}
}

s3_bucket_sse_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "server_side_encryption_configuration")
	ssec := module[keyToCheck]
	algorithm := ssec.rule.apply_server_side_encryption_by_default
	not check_master_key(algorithm)
	algorithm.sse_algorithm == "AES256"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'kms_master_key_id'is not null when algorithm is 'AES256'", "keyExpectedValue": "'kms_master_key_id' should be null when algorithm is 'AES256'", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.kms_master_key_id", [name]), "searchLine": common_lib.build_search_line(["module", name, "server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "kms_master_key_id"], [])}
}

s3_bucket_sse_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "server_side_encryption_configuration")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'server_side_encryption_configuration' is undefined or null", "keyExpectedValue": "'server_side_encryption_configuration' should be defined and not null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

s3_bucket_sse_disabled_inner[result] {
	bucket := input.document[i].resource.aws_s3_bucket[bucketName]
	not is_associated(bucketName, input.document[i])
	not tf_lib.has_target_resource(bucketName, "aws_s3_bucket_server_side_encryption_configuration")
	not common_lib.valid_key(bucket, "server_side_encryption_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'aws_s3_bucket' does not have 'server_side_encryption_configuration' associated", "keyExpectedValue": "'aws_s3_bucket' to have 'server_side_encryption_configuration' associated", "resourceName": tf_lib.get_specific_resource_name(bucket, "aws_s3_bucket", bucketName), "resourceType": "aws_s3_bucket", "searchKey": sprintf("aws_s3_bucket[%s]", [bucketName]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", bucketName], [])}
	# version after TF AWS 4.0
	# version before TF AWS 4.0

}

# version after TF AWS 4.0
s3_bucket_sse_disabled_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	sse := input.document[i].resource.aws_s3_bucket_server_side_encryption_configuration[name]
	split(sse.bucket, ".")[1] == bucketName
	not common_lib.valid_key(sse.rule, "apply_server_side_encryption_by_default")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'apply_server_side_encryption_by_default' is undefined or null", "keyExpectedValue": "'apply_server_side_encryption_by_default' should be defined and not null", "resourceName": tf_lib.get_resource_name(sse, name), "resourceType": "aws_s3_bucket_server_side_encryption_configuration", "searchKey": sprintf("aws_s3_bucket_server_side_encryption_configuration[%s].rule", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_server_side_encryption_configuration", name, "rule"], [])}
}

# version after TF AWS 4.0
s3_bucket_sse_disabled_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	sse := input.document[i].resource.aws_s3_bucket_server_side_encryption_configuration[name]
	split(sse.bucket, ".")[1] == bucketName
	algorithm := sse.rule.apply_server_side_encryption_by_default
	not check_master_key(algorithm)
	algorithm.sse_algorithm == "AES256"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'kms_master_key_id' is not null when algorithm is 'AES256'", "keyExpectedValue": "'kms_master_key_id' should be null when algorithm is 'AES256'", "resourceName": tf_lib.get_resource_name(sse, name), "resourceType": "aws_s3_bucket_server_side_encryption_configuration", "searchKey": sprintf("aws_s3_bucket_server_side_encryption_configuration[%s].rule.apply_server_side_encryption_by_default.kms_master_key_id", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_server_side_encryption_configuration", name, "rule", "apply_server_side_encryption_by_default", "kms_master_key_id"], [])}
}

# version after TF AWS 4.0
s3_bucket_sse_disabled_inner[result] {
	input.document[_0].resource.aws_s3_bucket[bucketName]
	sse := input.document[i].resource.aws_s3_bucket_server_side_encryption_configuration[name]
	split(sse.bucket, ".")[1] == bucketName
	rule := sse.rule.apply_server_side_encryption_by_default
	check_master_key(rule)
	rule.sse_algorithm != "AES256"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'sse_algorithm' is %s when key is null", [rule.sse_algorithm]), "keyExpectedValue": "'sse_algorithm' should be AES256 when key is null", "resourceName": tf_lib.get_resource_name(sse, name), "resourceType": "aws_s3_bucket_server_side_encryption_configuration", "searchKey": sprintf("aws_s3_bucket_server_side_encryption_configuration[%s].rule.apply_server_side_encryption_by_default.sse_algorithm", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_server_side_encryption_configuration", name, "rule", "apply_server_side_encryption_by_default", "sse_algorithm"], [])}
}

check_master_key(assed) {
	not common_lib.valid_key(assed, "kms_master_key_id")
} else {
	common_lib.emptyOrNull(assed.kms_master_key_id)
}

is_associated(aws_s3_bucket_name, doc) {
	[_, value] := walk(doc)
	sse_configurations := value.aws_s3_bucket_server_side_encryption_configuration[_]
	contains(sse_configurations.bucket, sprintf("aws_s3_bucket.%s", [aws_s3_bucket_name]))
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket SSE Disabled"
# description: >-
#   If algorithm is AES256 then the master key is null, empty or undefined, otherwise the master key is required
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_sse_disabled"
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
s3_bucket_sse_disabled_snippet[violation] {
	s3_bucket_sse_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

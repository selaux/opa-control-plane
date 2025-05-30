package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_allows_public_acl.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

#default of block_public_acls is false
s3_bucket_allows_public_acl_inner[result] {
	pubACL := input.document[i].resource.aws_s3_bucket_public_access_block[name]
	not common_lib.valid_key(pubACL, "block_public_acls")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'block_public_acls' is missing", "keyExpectedValue": "'block_public_acls' should equal 'true'", "remediation": "block_public_acls = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(pubACL, name), "resourceType": "aws_s3_bucket_public_access_block", "searchKey": sprintf("aws_s3_bucket_public_access_block[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_public_access_block", name], [])}
}

s3_bucket_allows_public_acl_inner[result] {
	pubACL := input.document[i].resource.aws_s3_bucket_public_access_block[name]
	pubACL.block_public_acls == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'block_public_acls' is equal 'false'", "keyExpectedValue": "'block_public_acls' should equal 'true'", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(pubACL, name), "resourceType": "aws_s3_bucket_public_access_block", "searchKey": sprintf("aws_s3_bucket_public_access_block[%s].block_public_acls", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_public_access_block", name, "block_public_acls"], [])}
}

s3_bucket_allows_public_acl_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "block_public_acls")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'block_public_acls' is missing", "keyExpectedValue": "'block_public_acls' should equal 'true'", "remediation": sprintf("%s = true", [keyToCheck]), "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

s3_bucket_allows_public_acl_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "block_public_acls")
	module[keyToCheck] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'block_public_acls' is equal 'false'", "keyExpectedValue": "'block_public_acls' should equal 'true'", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Allows Public ACL"
# description: >-
#   S3 bucket allows public ACL
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_allows_public_acl"
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
#       identifier: aws_s3_bucket_public_access_block
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
s3_bucket_allows_public_acl_snippet[violation] {
	s3_bucket_allows_public_acl_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

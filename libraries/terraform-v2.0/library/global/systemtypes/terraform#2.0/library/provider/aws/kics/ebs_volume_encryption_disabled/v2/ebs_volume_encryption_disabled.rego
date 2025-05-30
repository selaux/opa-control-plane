package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ebs_volume_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ebs_volume_encryption_disabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_ebs_volume[name]
	not common_lib.valid_key(resource, "encrypted")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": "One of 'aws_ebs_volume.encrypted' is undefined", "keyExpectedValue": "One of 'aws_ebs_volume.encrypted' should be defined", "remediation": "encrypted = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ebs_volume", "searchKey": sprintf("aws_ebs_volume[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ebs_volume", name], [])}
}

ebs_volume_encryption_disabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_ebs_volume[name]
	resource.encrypted == false
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": "One of 'aws_ebs_volume.encrypted' is 'false'", "keyExpectedValue": "One of 'aws_ebs_volume.encrypted' should be 'true'", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ebs_volume", "searchKey": sprintf("aws_ebs_volume[%s].encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ebs_volume", name, "encrypted"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EBS Volume Encryption Disabled"
# description: >-
#   EBS volumes should be encrypted
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ebs_volume_encryption_disabled"
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
#       identifier: aws_ebs_volume
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
ebs_volume_encryption_disabled_snippet[violation] {
	ebs_volume_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

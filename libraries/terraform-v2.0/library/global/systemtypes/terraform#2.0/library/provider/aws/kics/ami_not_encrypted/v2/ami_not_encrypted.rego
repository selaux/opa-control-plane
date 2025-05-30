package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ami_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ami_not_encrypted_inner[result] {
	ami := input.document[i].resource.aws_ami[name]
	ami.ebs_block_device.encrypted == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "One of 'rule.ebs_block_device.encrypted' is not 'true'", "keyExpectedValue": "One of 'rule.ebs_block_device.encrypted' should be 'true'", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(ami, name), "resourceType": "aws_ami", "searchKey": sprintf("aws_ami[%s].ebs_block_device.encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ami", name, "ebs_block_device", "encrypted"], [])}
}

ami_not_encrypted_inner[result] {
	ami := input.document[i].resource.aws_ami[name]
	common_lib.valid_key(ami, "ebs_block_device")
	not common_lib.valid_key(ami.ebs_block_device, "encrypted")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'rule.ebs_block_device' is undefined", "keyExpectedValue": "One of 'rule.ebs_block_device.encrypted' should be 'true'", "remediation": "encrypted = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(ami, name), "resourceType": "aws_ami", "searchKey": sprintf("aws_ami[%s].ebs_block_device", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ami", name, "ebs_block_device"], [])}
}

ami_not_encrypted_inner[result] {
	ami := input.document[i].resource.aws_ami[name]
	not common_lib.valid_key(ami, "ebs_block_device")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "One of 'rule.ebs_block_device' is undefined", "keyExpectedValue": "One of 'rule.ebs_block_device.encrypted' should be 'true'", "remediation": "ebs_block_device{ \n\t\tencrypted = true\n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(ami, name), "resourceType": "aws_ami", "searchKey": sprintf("aws_ami[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ami", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: AMI Not Encrypted"
# description: >-
#   AWS AMI Encryption is not enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ami_not_encrypted"
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
#       identifier: aws_ami
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
ami_not_encrypted_snippet[violation] {
	ami_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

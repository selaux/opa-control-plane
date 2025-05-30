package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ebs_volume_snapshot_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ebs_volume_snapshot_not_encrypted_inner[result] {
	doc := input.document[i]
	volume := doc.resource.aws_ebs_volume[volName]
	snapshot := doc.resource.aws_ebs_snapshot[snapName]
	volName == split(snapshot.volume_id, ".")[1]
	volume.encrypted == false
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_ebs_volume[%s].encrypted' associated with aws_ebs_snapshot[%s] is false", [volName, snapName]), "keyExpectedValue": sprintf("'aws_ebs_volume[%s].encrypted' associated with aws_ebs_snapshot[%s] should be true", [volName, snapName]), "resourceName": snapName, "resourceType": "aws_ebs_volume", "searchKey": sprintf("aws_ebs_volume[%s].encrypted", [snapName])}
}

ebs_volume_snapshot_not_encrypted_inner[result] {
	doc := input.document[i]
	volume := doc.resource.aws_ebs_volume[volName]
	snapshot := doc.resource.aws_ebs_snapshot[snapName]
	volName == split(snapshot.volume_id, ".")[1]
	not common_lib.valid_key(volume, "encrypted")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_ebs_volume[%s].encrypted' associated with aws_ebs_snapshot[%s] is undefined", [volName, snapName]), "keyExpectedValue": sprintf("'aws_ebs_volume[%s].encrypted' associated with aws_ebs_snapshot[%s] should be set", [volName, snapName]), "resourceName": snapName, "resourceType": "aws_ebs_snapshot", "searchKey": sprintf("aws_ebs_snapshot[%s]", [snapName])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EBS Volume Snapshot Not Encrypted"
# description: >-
#   The value on AWS EBS Volume Snapshot Encryptation must be true
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ebs_volume_snapshot_not_encrypted"
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
#       identifier: aws_ebs_snapshot
#       name: ""
#       scope: resource
#       service: ""
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
ebs_volume_snapshot_not_encrypted_snippet[violation] {
	ebs_volume_snapshot_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

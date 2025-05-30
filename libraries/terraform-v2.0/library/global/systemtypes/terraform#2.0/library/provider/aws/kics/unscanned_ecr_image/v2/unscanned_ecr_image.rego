package global.systemtypes["terraform:2.0"].library.provider.aws.kics.unscanned_ecr_image.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

unscanned_ecr_image_inner[result] {
	resource := input.document[i].resource.aws_ecr_repository[name]
	imageScan := resource.image_scanning_configuration
	not imageScan.scan_on_push
	result := {"documentId": input.document[i].id, "enabled": imageScan.scan_on_push, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_ecr_repository[%s].image_scanning_configuration.scan_on_push is false", [name]), "keyExpectedValue": sprintf("aws_ecr_repository[%s].image_scanning_configuration.scan_on_push is true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecr_repository", "searchKey": sprintf("aws_ecr_repository[%s].image_scanning_configuration.scan_on_push", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecr_repository", name, "image_scanning_configuration", "scan_on_push"], [])}
}

unscanned_ecr_image_inner[result] {
	imageScan := input.document[i].resource.aws_ecr_repository[name]
	not imageScan.image_scanning_configuration
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_ecr_repository[%s].image_scanning_configuration is undefined", [name]), "keyExpectedValue": sprintf("aws_ecr_repository[%s].image_scanning_configuration should be defined", [name]), "remediation": "image_scanning_configuration { \n\t\tscan_on_push = true \n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(imageScan, name), "resourceType": "aws_ecr_repository", "searchKey": sprintf("aws_ecr_repository[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecr_repository", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Unscanned ECR Image"
# description: >-
#   Checks if the ECR Image has been scanned
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.unscanned_ecr_image"
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
#       identifier: aws_ecr_repository
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
unscanned_ecr_image_snippet[violation] {
	unscanned_ecr_image_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

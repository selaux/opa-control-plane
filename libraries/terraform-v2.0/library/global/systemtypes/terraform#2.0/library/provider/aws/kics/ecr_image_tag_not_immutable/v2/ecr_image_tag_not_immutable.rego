package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecr_image_tag_not_immutable.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecr_image_tag_not_immutable_inner[result] {
	resource := input.document[i].resource.aws_ecr_repository[name]
	not common_lib.valid_key(resource, "image_tag_mutability")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_ecr_repository.%s.image_tag_mutability is undefined or null", [name]), "keyExpectedValue": sprintf("aws_ecr_repository.%s.image_tag_mutability should be defined and not null", [name]), "remediation": "image_tag_mutability = IMMUTABLE", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecr_repository", "searchKey": sprintf("aws_ecr_repository.%s", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecr_repository", name], [])}
}

ecr_image_tag_not_immutable_inner[result] {
	resource := input.document[i].resource.aws_ecr_repository[name]
	resource.image_tag_mutability == "MUTABLE"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_ecr_repository.%s.image_tag_mutability is 'MUTABLE'", [name]), "keyExpectedValue": sprintf("aws_ecr_repository.%s.image_tag_mutability should be 'IMMUTABLE'", [name]), "remediation": json.marshal({"after": "IMMUTABLE", "before": "MUTABLE"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecr_repository", "searchKey": sprintf("aws_ecr_repository.%s.image_tag_mutability", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecr_repository", name, "image_tag_mutability"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECR Image Tag Not Immutable"
# description: >-
#   ECR should have an image tag be immutable. This prevents image tags from being overwritten.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecr_image_tag_not_immutable"
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
ecr_image_tag_not_immutable_snippet[violation] {
	ecr_image_tag_not_immutable_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecr_repository_without_policy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecr_repository_without_policy_inner[result] {
	resource := input.document[i].resource
	ecr_repo := resource.aws_ecr_repository[name]
	check_policy(resource, name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_ecr_repository[%s] doesn't have policies attached", [name]), "keyExpectedValue": sprintf("aws_ecr_repository[%s] has policies attached", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecr_repository", "searchKey": sprintf("aws_ecr_repository[%s]", [name])}
}

check_policy(resource, name) {
	not common_lib.valid_key(resource, "aws_ecr_repository_policy")
} else {
	res_pol := {x | resource.aws_ecr_repository_policy[name_poly].repository == sprintf("${aws_ecr_repository.%s.name}", [name]); x := name_poly}
	count(res_pol) == 0
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECR Repository Without Policy"
# description: >-
#   ECR Repository should have Policies attached to it
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecr_repository_without_policy"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
ecr_repository_without_policy_snippet[violation] {
	ecr_repository_without_policy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

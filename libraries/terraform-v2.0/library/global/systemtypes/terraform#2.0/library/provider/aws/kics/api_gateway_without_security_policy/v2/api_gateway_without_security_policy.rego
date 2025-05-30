package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_without_security_policy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_without_security_policy_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_domain_name[name]
	not common_lib.valid_key(resource, "security_policy")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_api_gateway_domain_name[%s].security_policy is undefined", [name]), "keyExpectedValue": sprintf("aws_api_gateway_domain_name[%s].security_policy should be set", [name]), "remediation": "security_policy = \"TLS_1_2\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_domain_name", "searchKey": sprintf("aws_api_gateway_domain_name[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_domain_name", name], [])}
}

api_gateway_without_security_policy_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_domain_name[name]
	resource.security_policy != "TLS_1_2"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_api_gateway_domain_name[%s].security_policy is set to %s", [name, resource.security_policy]), "keyExpectedValue": sprintf("aws_api_gateway_domain_name[%s].security_policy should be set to TLS_1_2", [name]), "remediation": json.marshal({"after": "TLS_1_2", "before": sprintf("%s", [resource.security_policy])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_domain_name", "searchKey": sprintf("aws_api_gateway_domain_name[%s].security_policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_domain_name", name, "security_policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Without Security Policy"
# description: >-
#   API Gateway should have a Security Policy defined and use TLS 1.2.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_without_security_policy"
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
#       identifier: aws_api_gateway_domain_name
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
api_gateway_without_security_policy_snippet[violation] {
	api_gateway_without_security_policy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

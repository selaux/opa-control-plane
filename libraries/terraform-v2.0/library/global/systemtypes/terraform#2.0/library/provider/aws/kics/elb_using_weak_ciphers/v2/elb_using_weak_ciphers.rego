package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elb_using_weak_ciphers.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elb_using_weak_ciphers_inner[result] {
	resource := input.document[i].resource.aws_load_balancer_policy[name]
	protocol := resource.policy_attribute.name
	common_lib.weakCipher(protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s].name' is a weak cipher", [name, protocol]), "keyExpectedValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s].name' should not be a weak cipher", [name, protocol]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_load_balancer_policy", "searchKey": sprintf("aws_load_balancer_policy[%s].policy_attribute.name", [name])}
}

elb_using_weak_ciphers_inner[result] {
	policy := input.document[i].resource.aws_load_balancer_policy[name]
	some j
	protocol := policy.policy_attribute[j].name
	common_lib.weakCipher(protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s].name' is a weak cipher", [name, protocol]), "keyExpectedValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s].name' should not be a weak cipher", [name, protocol]), "resourceName": tf_lib.get_resource_name(policy, name), "resourceType": "aws_load_balancer_policy", "searchKey": sprintf("aws_load_balancer_policy[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ELB Using Weak Ciphers"
# description: >-
#   ELB Predefined or Custom Security Policies must not use weak ciphers, to reduce the risk of the SSL connection between the client and the load balancer being exploited. That means the 'name' of 'policy_attributes' must not coincide with any of a predefined list of weak ciphers.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elb_using_weak_ciphers"
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
#       identifier: aws_load_balancer_policy
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
elb_using_weak_ciphers_snippet[violation] {
	elb_using_weak_ciphers_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

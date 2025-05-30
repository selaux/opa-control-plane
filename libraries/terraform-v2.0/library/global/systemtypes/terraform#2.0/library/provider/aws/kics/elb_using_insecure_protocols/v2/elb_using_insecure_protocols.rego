package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elb_using_insecure_protocols.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

insecure_protocols := ["Protocol-SSLv2", "Protocol-SSLv3", "Protocol-TLSv1", "Protocol-TLSv1.1"]

elb_using_insecure_protocols_inner[result] {
	policy := input.document[i].resource.aws_load_balancer_policy[name]
	protocol := policy.policy_attribute.name
	commonLib.inArray(insecure_protocols, protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s]' is an insecure protocol", [name, protocol]), "keyExpectedValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s]' should not be an insecure protocol", [name, protocol]), "remediation": json.marshal({"after": "Protocol-TLSv1.2", "before": sprintf("%s", [protocol])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(policy, name), "resourceType": "aws_load_balancer_policy", "searchKey": sprintf("aws_load_balancer_policy[%s].policy_attribute.name", [name]), "searchLine": commonLib.build_search_line(["resource", "aws_load_balancer_policy", name, "policy_attribute", "name"], [])}
}

elb_using_insecure_protocols_inner[result] {
	policy := input.document[i].resource.aws_load_balancer_policy[name]
	some j
	protocol := policy.policy_attribute[j].name
	commonLib.inArray(insecure_protocols, protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s]' is an insecure protocol", [name, protocol]), "keyExpectedValue": sprintf("'aws_load_balancer_policy[%s].policy_attribute[%s]' should not be an insecure protocol", [name, protocol]), "remediation": json.marshal({"after": "Protocol-TLSv1.2", "before": sprintf("%s", [protocol])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(policy, name), "resourceType": "aws_load_balancer_policy", "searchKey": sprintf("aws_load_balancer_policy[%s].policy_attribute[%d].name", [name, j]), "searchLine": commonLib.build_search_line(["resource", "aws_load_balancer_policy", name, "policy_attribute", j, "name"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ELB Using Insecure Protocols"
# description: >-
#   ELB Predefined or Custom Security Policies must not use insecure protocols, to reduce the risk of the SSL connection between the client and the load balancer being exploited. That means the 'name' of 'policy_attributes' must not coincide with any of a predefined list of insecure protocols.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elb_using_insecure_protocols"
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
elb_using_insecure_protocols_snippet[violation] {
	elb_using_insecure_protocols_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

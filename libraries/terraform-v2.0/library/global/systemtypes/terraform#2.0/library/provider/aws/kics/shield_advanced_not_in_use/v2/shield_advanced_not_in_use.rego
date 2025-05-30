package global.systemtypes["terraform:2.0"].library.provider.aws.kics.shield_advanced_not_in_use.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

resources := {
	"aws_cloudfront_distribution",
	"aws_lb",
	"aws_globalaccelerator_accelerator",
	"aws_eip",
	"aws_route53_zone",
}

shield_advanced_not_in_use_inner[result] {
	target := input.document[i].resource[resources[idx]][name]
	not has_shield_advanced(name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s does not have shield advanced associated", [resources[idx]]), "keyExpectedValue": sprintf("%s has shield advanced associated", [resources[idx]]), "resourceName": tf_lib.get_resource_name(target, name), "resourceType": resources[idx], "searchKey": sprintf("%s[%s]", [resources[idx], name]), "searchLine": common_lib.build_search_line(["resource", resources[idx], name], [])}
}

has_shield_advanced(name) {
	shield := input.document[_].resource.aws_shield_protection[_]
	matches(shield, name)
}

matches(shield, name) {
	split(shield.resource_arn, ".")[1] == name
} else {
	target := split(shield.resource_arn, "/")[1]
	split(target, ".")[1] == name
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Shield Advanced Not In Use"
# description: >-
#   AWS Shield Advanced should be used for Amazon Route 53 hosted zone, AWS Global Accelerator accelerator, Elastic IP Address, Elastic Load Balancing, and Amazon CloudFront Distribution to protect these resources against robust DDoS attacks
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.shield_advanced_not_in_use"
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
#       identifier: aws_eip
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_route53_zone
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
shield_advanced_not_in_use_snippet[violation] {
	shield_advanced_not_in_use_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

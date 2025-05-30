package global.systemtypes["terraform:2.0"].library.provider.aws.kics.alb_is_not_integrated_with_waf.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

alb_is_not_integrated_with_waf_inner[result] {
	lb := {"aws_alb", "aws_lb"}
	resource := input.document[i].resource[lb[idx]][name]
	not is_internal_alb(resource)
	not associated_waf(name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'%s[%s]' is not 'internal' and does not have a 'aws_wafregional_web_acl_association' associated", [lb[idx], name]), "keyExpectedValue": sprintf("'%s[%s]' should not be 'internal' and has a 'aws_wafregional_web_acl_association' associated", [lb[idx], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": lb[idx], "searchKey": sprintf("%s[%s]", [lb[idx], name])}
}

is_internal_alb(resource) {
	resource.internal == true
}

associated_waf(name) {
	waf := input.document[_].resource.aws_wafregional_web_acl_association[waf_name]
	attribute := waf.resource_arn
	attribute_split := split(attribute, ".")
	options := {"${aws_alb", "${aws_lb"}
	attribute_split[0] == options[x]
	attribute_split[1] == name
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ALB Is Not Integrated With WAF"
# description: >-
#   All Application Load Balancers (ALB) must be protected with Web Application Firewall (WAF) service
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.alb_is_not_integrated_with_waf"
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
#       identifier: aws_alb
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
alb_is_not_integrated_with_waf_snippet[violation] {
	alb_is_not_integrated_with_waf_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

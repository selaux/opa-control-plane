package global.systemtypes["terraform:2.0"].library.provider.aws.kics.alb_deletion_protection_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

lbs := {"aws_lb", "aws_alb"}

alb_deletion_protection_disabled_inner[result] {
	loadBalancer := lbs[l]
	lb := input.document[i].resource[loadBalancer][name]
	not common_lib.valid_key(lb, "enable_deletion_protection")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'enable_deletion_protection' is undefined or null", "keyExpectedValue": "'enable_deletion_protection' should be defined and set to true", "remediation": "enable_deletion_protection = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(lb, name), "resourceType": loadBalancer, "searchKey": sprintf("%s[%s]", [loadBalancer, name]), "searchLine": common_lib.build_search_line(["resource", loadBalancer, name], [])}
}

alb_deletion_protection_disabled_inner[result] {
	loadBalancer := lbs[l]
	lb := input.document[i].resource[loadBalancer][name]
	lb.enable_deletion_protection == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'enable_deletion_protection' is set to false", "keyExpectedValue": "'enable_deletion_protection' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(lb, name), "resourceType": loadBalancer, "searchKey": sprintf("%s[%s].enable_deletion_protection", [loadBalancer, name]), "searchLine": common_lib.build_search_line(["resource", loadBalancer, name, "enable_deletion_protection"], [])}
}

alb_deletion_protection_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_lb", "enable_deletion_protection")
	not common_lib.valid_key(module, "enable_deletion_protection")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'enable_deletion_protection' is undefined or null", "keyExpectedValue": "'enable_deletion_protection' should be defined and set to true", "remediation": "enable_deletion_protection = true", "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

alb_deletion_protection_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_lb", "enable_deletion_protection")
	module.enable_deletion_protection == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'enable_deletion_protection' is set to false", "keyExpectedValue": "'enable_deletion_protection' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].enable_deletion_protection", [name]), "searchLine": common_lib.build_search_line(["module", name, "enable_deletion_protection"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ALB Deletion Protection Disabled"
# description: >-
#   Application Load Balancer should have deletion protection enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.alb_deletion_protection_disabled"
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
#       identifier: aws_alb
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_lb
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
alb_deletion_protection_disabled_snippet[violation] {
	alb_deletion_protection_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

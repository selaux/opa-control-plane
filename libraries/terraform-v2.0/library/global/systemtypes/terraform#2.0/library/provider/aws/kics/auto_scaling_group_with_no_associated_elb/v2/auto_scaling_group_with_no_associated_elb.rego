package global.systemtypes["terraform:2.0"].library.provider.aws.kics.auto_scaling_group_with_no_associated_elb.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

auto_scaling_group_with_no_associated_elb_inner[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]
	count(resource.load_balancers) == 0
	not has_target_group_arns(resource, "target_group_arns")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_autoscaling_group[%s].load_balancers is empty", [name]), "keyExpectedValue": sprintf("aws_autoscaling_group[%s].load_balancers should be set and not empty", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_autoscaling_group", "searchKey": sprintf("aws_autoscaling_group[%s].load_balancers", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "load_balancers"], [])}
}

auto_scaling_group_with_no_associated_elb_inner[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]
	not common_lib.valid_key(resource, "load_balancers")
	not has_target_group_arns(resource, "target_group_arns")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_autoscaling_group[%s].load_balancers is undefined", [name]), "keyExpectedValue": sprintf("aws_autoscaling_group[%s].load_balancers should be set and not empty", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_autoscaling_group", "searchKey": sprintf("aws_autoscaling_group[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], [])}
}

auto_scaling_group_with_no_associated_elb_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "load_balancers")
	keyToCheckGroupArns := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "target_group_arns")
	not has_target_group_arns(module, keyToCheckGroupArns)
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'load_balancers' is undefined", "keyExpectedValue": "'load_balancers' should be set and not empty", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

auto_scaling_group_with_no_associated_elb_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "load_balancers")
	keyToCheckGroupArns := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "target_group_arns")
	not has_target_group_arns(module, keyToCheckGroupArns)
	count(module[keyToCheck]) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'load_balancers' is undefined", "keyExpectedValue": "'load_balancers' should be set and not empty", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].load_balancers", [name]), "searchLine": common_lib.build_search_line(["module", name, "load_balancers"], [])}
}

has_target_group_arns(resource, key) {
	not is_array(resource[key])
	resource[key] != ""
} else {
	is_array(resource[key])
	count(resource[key]) > 0
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Auto Scaling Group With No Associated ELB"
# description: >-
#   AWS Auto Scaling Groups must have associated ELBs to ensure high availability and improve application performance. This means the attribute 'load_balancers' must be defined and not empty.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.auto_scaling_group_with_no_associated_elb"
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
#       identifier: aws_autoscaling_group
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
auto_scaling_group_with_no_associated_elb_snippet[violation] {
	auto_scaling_group_with_no_associated_elb_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

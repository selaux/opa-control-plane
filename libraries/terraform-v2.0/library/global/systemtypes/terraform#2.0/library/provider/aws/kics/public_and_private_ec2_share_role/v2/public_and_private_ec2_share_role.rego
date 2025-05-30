package global.systemtypes["terraform:2.0"].library.provider.aws.kics.public_and_private_ec2_share_role.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

public_and_private_ec2_share_role_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	contains(resource.subnet_id, "public_subnets")
	instanceProfileName := split(resource.iam_instance_profile, ".")[1]
	check_private_instance(instanceProfileName, i)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Public and private instances share the same role", "keyExpectedValue": "Public and private instances should not share the same role", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s].iam_instance_profile", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "iam_instance_profile"], [])}
}

public_and_private_ec2_share_role_inner[result] {
	module := input.document[i].module[name]
	subnetId := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "subnet_id")
	contains(module[subnetId], "public_subnets")
	iamInstanceProfile := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "iam_instance_profile")
	instanceProfileName := split(module[iamInstanceProfile], ".")[1]
	check_private_instance(instanceProfileName, i)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Public and private instances share the same role", "keyExpectedValue": "Public and private instances should not share the same role", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].iam_instance_profile", [name]), "searchLine": common_lib.build_search_line(["module", name, "iam_instance_profile"], [])}
}

check_private_instance(instanceProfileName, i) {
	instance := input.document[i].resource.aws_instance[name]

	contains(instance.subnet_id, "private_subnets")

	split(instance.iam_instance_profile, ".")[1] == instanceProfileName
} else {
	instance := input.document[i].module[name]
	subnetId := common_lib.get_module_equivalent_key("aws", instance.source, "aws_instance", "subnet_id")

	contains(instance[subnetId], "private_subnets")
	iamInstanceProfile := common_lib.get_module_equivalent_key("aws", instance.source, "aws_instance", "iam_instance_profile")

	split(instance[iamInstanceProfile], ".")[1] == instanceProfileName
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Public and Private EC2 Share Role"
# description: >-
#   Public and private EC2 instances should not share the same role.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.public_and_private_ec2_share_role"
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
public_and_private_ec2_share_role_snippet[violation] {
	public_and_private_ec2_share_role_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

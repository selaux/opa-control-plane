package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ec2_instance_has_public_ip.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ec2_instance_has_public_ip_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	not common_lib.valid_key(resource, "associate_public_ip_address")
	not common_lib.valid_key(resource, "network_interface")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'associate_public_ip_address' is undefined or null", "keyExpectedValue": "'associate_public_ip_address' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance.%s", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name], [])}
}

ec2_instance_has_public_ip_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "associate_public_ip_address")
	netInterfaceKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "network_interface")
	not common_lib.valid_key(module, netInterfaceKey)
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'associate_public_ip_address' is undefined or null", "keyExpectedValue": "'associate_public_ip_address' should be defined and not null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

ec2_instance_has_public_ip_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	isTrue(resource.associate_public_ip_address)
	not common_lib.valid_key(resource, "network_interface")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'associate_public_ip_address' is true", "keyExpectedValue": "'associate_public_ip_address' should be set to false", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance.%s.associate_public_ip_address", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "associate_public_ip_address"], [])}
}

ec2_instance_has_public_ip_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "associate_public_ip_address")
	netInterfaceKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "network_interface")
	not common_lib.valid_key(module, netInterfaceKey)
	isTrue(module[keyToCheck])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'associate_public_ip_address' is true", "keyExpectedValue": "'associate_public_ip_address' should be set to false", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].associate_public_ip_address", [name]), "searchLine": common_lib.build_search_line(["module", name, "associate_public_ip_address"], [])}
}

isTrue(answer) {
	lower(answer) == "yes"
} else {
	lower(answer) == "true"
} else {
	answer == true
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EC2 Instance Has Public IP"
# description: >-
#   EC2 Instance should not have a public IP address.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ec2_instance_has_public_ip"
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
#       identifier: aws_instance
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
ec2_instance_has_public_ip_snippet[violation] {
	ec2_instance_has_public_ip_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

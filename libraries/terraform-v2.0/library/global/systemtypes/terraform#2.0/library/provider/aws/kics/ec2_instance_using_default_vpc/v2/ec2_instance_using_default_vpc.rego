package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ec2_instance_using_default_vpc.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ec2_instance_using_default_vpc_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]
	sbName := split(resource.subnet_id, ".")[1]
	sb := input.document[_].resource.aws_subnet[sbName]
	contains(lower(sb.vpc_id), "default")
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_instance[%s].subnet_id is associated with a default VPC", [name]), "keyExpectedValue": sprintf("aws_instance[%s].subnet_id should not be associated with a default VPC", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s].subnet_id", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "subnet_id"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EC2 Instance Using Default VPC"
# description: >-
#   EC2 Instances should not be configured under a default VPC network
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ec2_instance_using_default_vpc"
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
ec2_instance_using_default_vpc_snippet[violation] {
	ec2_instance_using_default_vpc_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

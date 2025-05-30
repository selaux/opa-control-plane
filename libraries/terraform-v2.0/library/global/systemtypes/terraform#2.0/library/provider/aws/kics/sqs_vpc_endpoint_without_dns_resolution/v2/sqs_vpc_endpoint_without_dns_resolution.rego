package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sqs_vpc_endpoint_without_dns_resolution.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sqs_vpc_endpoint_without_dns_resolution_inner[result] {
	resource := input.document[i].resource.aws_vpc_endpoint[name]
	serviceNameSplit := split(resource.service_name, ".")
	serviceNameSplit[count(serviceNameSplit) - 1] == "sqs"
	vpcNameRef := split(resource.vpc_id, ".")[1]
	vpc := input.document[j].resource.aws_vpc[vpcNameRef]
	vpc.enable_dns_support == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'enable_dns_support' is set to false", "keyExpectedValue": "'enable_dns_support' should be set to true or undefined", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_vpc_endpoint", "searchKey": sprintf("aws_vpc_endpoint[%s].vpc_id", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_vpc_endpoint", name, "vpc_id"], [])}
}

sqs_vpc_endpoint_without_dns_resolution_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_vpc", "enable_dns_support")
	module[keyToCheck] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'enable_dns_support' is set to false", "keyExpectedValue": "'enable_dns_support' should be set to true or undefined", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].enable_dns_support", [name]), "searchLine": common_lib.build_search_line(["module", name, "vpc_id"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQS VPC Endpoint Without DNS Resolution"
# description: >-
#   SQS VPC Endpoint should have DNS resolution enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sqs_vpc_endpoint_without_dns_resolution"
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
sqs_vpc_endpoint_without_dns_resolution_snippet[violation] {
	sqs_vpc_endpoint_without_dns_resolution_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

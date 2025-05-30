package global.systemtypes["terraform:2.0"].library.provider.aws.kics.instance_with_no_vpc.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

instance_with_no_vpc_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	not common_lib.valid_key(resource, "vpc_security_group_ids")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'vpc_security_group_ids' is undefined or null", "keyExpectedValue": "Attribute 'vpc_security_group_ids' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name], [])}
}

instance_with_no_vpc_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "vpc_security_group_ids")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'vpc_security_group_ids' is undefined or null", "keyExpectedValue": "Attribute 'vpc_security_group_ids' should be defined and not null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Instance With No VPC"
# description: >-
#   EC2 Instances should be configured under a VPC network. AWS VPCs provide the controls to facilitate a formal process for approving and testing all network connections and changes to the firewall and router configurations.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.instance_with_no_vpc"
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
instance_with_no_vpc_snippet[violation] {
	instance_with_no_vpc_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

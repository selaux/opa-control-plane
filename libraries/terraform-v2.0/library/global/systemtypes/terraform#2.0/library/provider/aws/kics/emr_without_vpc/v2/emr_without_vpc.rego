package global.systemtypes["terraform:2.0"].library.provider.aws.kics.emr_without_vpc.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

emr_without_vpc_inner[result] {
	resource := input.document[i].resource.aws_emr_cluster[name]
	attrs := {"subnet_id", "subnet_ids"}
	count({x | attr := attrs[x]; common_lib.valid_key(resource, attr)}) == 0
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_emr_cluster[%s].subnet_id' or 'aws_emr_cluster[%s].subnet_ids' is undefined or null", [name, name]), "keyExpectedValue": sprintf("'aws_emr_cluster[%s].subnet_id' or 'aws_emr_cluster[%s].subnet_ids' should be defined and not null'", [name, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_emr_cluster", "searchKey": sprintf("aws_emr_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_emr_cluster", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EMR Without VPC"
# description: >-
#   Elastic MapReduce Cluster (EMR) should be launched in a Virtual Private Cloud (VPC)
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.emr_without_vpc"
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
#       identifier: aws_emr_cluster
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
emr_without_vpc_snippet[violation] {
	emr_without_vpc_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

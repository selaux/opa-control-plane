package global.systemtypes["terraform:2.0"].library.provider.aws.kics.service_control_policies_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

service_control_policies_disabled_inner[result] {
	org := input.document[i].resource.aws_organizations_organization[name]
	org.feature_set == "CONSOLIDATED_BILLING"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'feature_set' is set to 'CONSOLIDATED_BILLING'", "keyExpectedValue": "'feature_set' should be set to 'ALL' or undefined", "remediation": json.marshal({"after": "ALL", "before": "CONSOLIDATED_BILLING"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(org, name), "resourceType": "aws_organizations_organization", "searchKey": sprintf("aws_organizations_organization[%s].feature_set", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_organizations_organization", name, "feature_set"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Service Control Policies Disabled"
# description: >-
#   Check if the Amazon Organizations ensure that all features are enabled to achieve full control over the use of AWS services and actions across multiple AWS accounts using Service Control Policies (SCPs).
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.service_control_policies_disabled"
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
#       identifier: aws_organizations_organization
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
service_control_policies_disabled_snippet[violation] {
	service_control_policies_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

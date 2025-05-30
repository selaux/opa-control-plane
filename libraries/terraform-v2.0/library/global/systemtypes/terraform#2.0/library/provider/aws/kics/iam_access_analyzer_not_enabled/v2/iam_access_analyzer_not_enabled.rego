package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_access_analyzer_not_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import input as tf

iam_access_analyzer_not_enabled_inner[result] {
	paths := [p | [path, value] := walk(tf); p := path]
	document_indexes := [nr | count(paths[x]) == 3; paths[x][0] == "document"; paths[x][2] == "resource"; nr := paths[x][1]]
	not_defined(document_indexes)
	doc := input.document[document_indexes[0]]
	contains(doc.file, ".tf")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": "'aws_accessanalyzer_analyzer' is undefined", "keyExpectedValue": "'aws_accessanalyzer_analyzer' should be set", "resourceName": "n/a", "resourceType": "n/a", "searchKey": "resource", "searchLine": common_lib.build_search_line(["resource"], [])}
}

not_defined(document_indexes) {
	count(document_indexes) != 0
	count({name | input.document[x].resource[name]; contains(name, "aws")}) > 0
	count({x | resource := input.document[x].resource; common_lib.valid_key(resource, "aws_accessanalyzer_analyzer")}) == 0
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Access Analyzer Not Enabled"
# description: >-
#   IAM Access Analyzer should be enabled and configured to continuously monitor resource permissions
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_access_analyzer_not_enabled"
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
iam_access_analyzer_not_enabled_snippet[violation] {
	iam_access_analyzer_not_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

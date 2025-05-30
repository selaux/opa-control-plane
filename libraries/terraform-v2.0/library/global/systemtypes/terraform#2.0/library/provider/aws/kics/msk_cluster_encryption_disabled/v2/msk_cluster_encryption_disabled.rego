package global.systemtypes["terraform:2.0"].library.provider.aws.kics.msk_cluster_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

msk_cluster_encryption_disabled_inner[result] {
	msk_cluster := input.document[i].resource.aws_msk_cluster[name]
	problems := checkEncryption(msk_cluster)
	problems != "none"
	result := {"documentId": input.document[i].id, "issueType": getIssueType(problems), "keyActualValue": "'rule.encryption_info' is unassigned or property 'in_cluster' is 'false' or property 'client_broker' is not 'TLS'", "keyExpectedValue": "Should have 'rule.encryption_info' and, if 'rule.encryption_info.encryption_in_transit' is assigned, 'in_cluster' should be 'true' and 'client_broker' should be TLS", "resourceName": tf_lib.get_specific_resource_name(msk_cluster, "aws_msk_cluster", name), "resourceType": "aws_msk_cluster", "searchKey": getSearchKey(problems, name)}
}

checkEncryption(msk_cluster) = ".encryption_in_transit.in_cluster,encryption_in_transit.client_broker" {
	encryptionInTransit = msk_cluster.encryption_info.encryption_in_transit
	encryptionInTransit.client_broker != "TLS"
	encryptionInTransit.in_cluster == false
} else = ".encryption_info.encryption_in_transit.client_broker" {
	encryptionInTransit = msk_cluster.encryption_info.encryption_in_transit
	encryptionInTransit.client_broker != "TLS"
} else = ".encryption_info.encryption_in_transit.in_cluster" {
	encryptionInTransit = msk_cluster.encryption_info.encryption_in_transit
	encryptionInTransit.in_cluster == false
} else = "" {
	not msk_cluster.encryption_info
} else = "none"

getSearchKey(problems, name) = str {
	problemsSplited := split(problems, ",")
	count(problemsSplited) == 2
	defaultSearchValue := sprintf("msk_cluster[%s].encryption_info", [name])
	str := concat(" and ", [concat("", [defaultSearchValue, problemsSplited[0]]), concat("", [defaultSearchValue, problemsSplited[1]])])
} else = str {
	defaultSearchValue := sprintf("msk_cluster[%s]", [name])
	str := concat("", [defaultSearchValue, problems])
}

getIssueType(problems) = "MissingAttribute" {
	problems == ""
} else = "IncorrectValue"

# METADATA: library-snippet
# version: v1
# title: "KICS: MSK Cluster Encryption Disabled"
# description: >-
#   Ensure MSK Cluster encryption in rest and transit is enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.msk_cluster_encryption_disabled"
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
#       identifier: aws_msk_cluster
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
msk_cluster_encryption_disabled_snippet[violation] {
	msk_cluster_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

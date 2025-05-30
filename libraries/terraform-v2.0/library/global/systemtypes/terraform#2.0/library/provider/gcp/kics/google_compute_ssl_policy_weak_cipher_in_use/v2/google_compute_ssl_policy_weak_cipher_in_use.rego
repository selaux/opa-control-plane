package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_compute_ssl_policy_weak_cipher_in_use.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_compute_ssl_policy_weak_cipher_in_use_inner[result] {
	sslPolicy := input.document[i].resource.google_compute_ssl_policy[name]
	sslPolicy.min_tls_version != "TLS_1_2"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_compute_ssl_policy[%s].min_tls_version is not TLS_1_2", [name]), "keyExpectedValue": sprintf("google_compute_ssl_policy[%s].min_tls_version should be TLS_1_2", [name]), "remediation": json.marshal({"after": "TLS_1_2", "before": sprintf("%s", [sslPolicy.min_tls_version])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(sslPolicy, name), "resourceType": "google_compute_ssl_policy", "searchKey": sprintf("google_compute_ssl_policy[%s].min_tls_version", [name]), "searchLine": common_lib.build_search_line(["resource", "google_compute_ssl_policy", name], ["min_tls_version"])}
}

google_compute_ssl_policy_weak_cipher_in_use_inner[result] {
	sslPolicy := input.document[i].resource.google_compute_ssl_policy[name]
	not common_lib.valid_key(sslPolicy, "min_tls_version")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("google_compute_ssl_policy[%s].min_tls_version is undefined", [name]), "keyExpectedValue": sprintf("google_compute_ssl_policy[%s].min_tls_version should be TLS_1_2", [name]), "remediation": "min_tls_version = \"TLS_1_2\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(sslPolicy, name), "resourceType": "google_compute_ssl_policy", "searchKey": sprintf("google_compute_ssl_policy[%s].min_tls_version", [name]), "searchLine": common_lib.build_search_line(["resource", "google_compute_ssl_policy", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Compute SSL Policy Weak Cipher In Use"
# description: >-
#   This query confirms if Google Compute SSL Policy Weak Cipher suites is Enabled, to do so we need to check if TLS is TLS_1_2, because other version have Weak Chypers
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_compute_ssl_policy_weak_cipher_in_use"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: google_compute_ssl_policy
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
google_compute_ssl_policy_weak_cipher_in_use_snippet[violation] {
	google_compute_ssl_policy_weak_cipher_in_use_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

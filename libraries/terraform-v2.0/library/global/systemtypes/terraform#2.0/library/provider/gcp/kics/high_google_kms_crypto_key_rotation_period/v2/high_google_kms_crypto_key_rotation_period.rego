package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.high_google_kms_crypto_key_rotation_period.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

high_google_kms_crypto_key_rotation_period_inner[result] {
	cryptoKey := input.document[i].resource.google_kms_crypto_key[name]
	rotationPeriod := substring(cryptoKey.rotation_period, 0, count(cryptoKey.rotation_period) - 1)
	to_number(rotationPeriod) > 7776000
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'google_kms_crypto_key.rotation_period' exceeds 7776000", "keyExpectedValue": "'google_kms_crypto_key.rotation_period' should be less or equal to 7776000", "remediation": json.marshal({"after": "100000", "before": sprintf("%s", [rotationPeriod])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cryptoKey, name), "resourceType": "google_kms_crypto_key", "searchKey": sprintf("google_kms_crypto_key[%s].rotation_period", [name]), "searchLine": common_lib.build_search_line(["resource", "google_kms_crypto_key", name, "rotation_period"], [])}
}

high_google_kms_crypto_key_rotation_period_inner[result] {
	cryptoKey := input.document[i].resource.google_kms_crypto_key[name]
	not common_lib.valid_key(cryptoKey, "rotation_period")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'google_kms_crypto_key.rotation_period' is undefined", "keyExpectedValue": "'google_kms_crypto_key.rotation_period' should be defined with a value less or equal to 7776000", "remediation": "rotation_period = \"100000s\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(cryptoKey, name), "resourceType": "google_kms_crypto_key", "searchKey": sprintf("google_kms_crypto_key[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "google_kms_crypto_key", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: High Google KMS Crypto Key Rotation Period"
# description: >-
#   KMS encryption keys should be rotated every 90 days or less. A short lifetime of encryption keys reduces the potential blast radius in case of compromise.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.high_google_kms_crypto_key_rotation_period"
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
#       identifier: google_kms_crypto_key
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
high_google_kms_crypto_key_rotation_period_snippet[violation] {
	high_google_kms_crypto_key_rotation_period_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

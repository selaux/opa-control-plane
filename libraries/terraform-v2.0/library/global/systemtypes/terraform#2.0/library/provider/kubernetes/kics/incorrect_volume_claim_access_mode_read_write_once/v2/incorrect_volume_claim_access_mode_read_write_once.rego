package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.incorrect_volume_claim_access_mode_read_write_once.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

incorrect_volume_claim_access_mode_read_write_once_inner[result] {
	resource := input.document[i].resource.kubernetes_stateful_set[name]
	volume_claim_template := resource.spec.volume_claim_template
	vClaimsWitReadWriteOnce := [vClaims | contains(volume_claim_template[vm].spec.access_modes[am], "ReadWriteOnce") == true; vClaims := volume_claim_template[vm].metadata.name]
	count(vClaimsWitReadWriteOnce) == 0
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template does not have a template with a 'ReadWriteOnce'", [name]), "keyExpectedValue": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template has one template with a 'ReadWriteOnce'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_stateful_set", "searchKey": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template", [name])}
}

incorrect_volume_claim_access_mode_read_write_once_inner[result] {
	resource := input.document[i].resource.kubernetes_stateful_set[name]
	volume_claim_template := resource.spec.volume_claim_template
	vClaimsWitReadWriteOnce := [vClaims | contains(volume_claim_template[vm].spec.access_modes[am], "ReadWriteOnce") == true; vClaims := volume_claim_template[vm].metadata.name]
	count(vClaimsWitReadWriteOnce) > 1
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template has multiple templates with 'ReadWriteOnce'", [name]), "keyExpectedValue": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template has only one template with a 'ReadWriteOnce'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_stateful_set", "searchKey": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Incorrect Volume Claim Access Mode ReadWriteOnce"
# description: >-
#   Kubernetes Stateful Sets must have one Volume Claim template with the access mode 'ReadWriteOnce'
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.incorrect_volume_claim_access_mode_read_write_once"
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
#     name: "kubernetes"
#     versions:
#       min: "v2"
#       max: "v2"
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
incorrect_volume_claim_access_mode_read_write_once_snippet[violation] {
	incorrect_volume_claim_access_mode_read_write_once_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

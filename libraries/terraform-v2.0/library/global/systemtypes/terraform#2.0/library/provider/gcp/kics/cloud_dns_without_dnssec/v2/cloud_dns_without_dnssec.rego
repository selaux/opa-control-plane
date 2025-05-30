package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.cloud_dns_without_dnssec.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

cloud_dns_without_dnssec_inner[result] {
	resource := input.document[i].resource.google_dns_managed_zone[name]
	withoutDNSSec(resource.dnssec_config)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'dnssec_config.state' is not equal to 'on'", "keyExpectedValue": "'dnssec_config.state' should equal to 'on'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_dns_managed_zone", "searchKey": sprintf("google_dns_managed_zone[%s].dnssec_config.state", [name]), "searchLine": common_lib.build_search_line(["resource", "google_dns_managed_zone", name, "dnssec_config", "state"], [])}
}

withoutDNSSec(dnssec_config) {
	is_array(dnssec_config)
	some i
	dnssec_config[i].state != "on"
}

withoutDNSSec(dnssec_config) {
	is_object(dnssec_config)
	dnssec_config.state != "on"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cloud DNS Without DNSSEC"
# description: >-
#   DNSSEC must be enabled for Cloud DNS
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.cloud_dns_without_dnssec"
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
#       identifier: google_dns_managed_zone
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
cloud_dns_without_dnssec_snippet[violation] {
	cloud_dns_without_dnssec_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

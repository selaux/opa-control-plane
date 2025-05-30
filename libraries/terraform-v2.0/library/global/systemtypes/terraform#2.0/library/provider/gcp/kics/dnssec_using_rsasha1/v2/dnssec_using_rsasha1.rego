package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.dnssec_using_rsasha1.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

dnssec_using_rsasha1_inner[result] {
	dnssec_config := input.document[i].resource.google_dns_managed_zone[name].dnssec_config
	dnssec_config.default_key_specs.algorithm == "rsasha1"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "dnssec_config.default_key_specs.algorithm is 'rsasha1'", "keyExpectedValue": "dnssec_config.default_key_specs.algorithm shouldn't be 'rsasha1'", "remediation": json.marshal({"after": "rsasha256", "before": "rsasha1"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(dnssec_config, name), "resourceType": "google_dns_managed_zone", "searchKey": sprintf("google_dns_managed_zone[%s].dnssec_config.default_key_specs.algorithm", [name]), "searchLine": common_lib.build_search_line(["resource", "google_dns_managed_zone", name], ["dnssec_config", "default_key_specs", "algorithm"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DNSSEC Using RSASHA1"
# description: >-
#   DNSSEC should not use the RSASHA1 algorithm, which means if, within the 'dnssec_config' block, the 'default_key_specs' block exists with the 'algorithm' field is 'rsasha1' which is bad.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.dnssec_using_rsasha1"
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
dnssec_using_rsasha1_snippet[violation] {
	dnssec_using_rsasha1_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

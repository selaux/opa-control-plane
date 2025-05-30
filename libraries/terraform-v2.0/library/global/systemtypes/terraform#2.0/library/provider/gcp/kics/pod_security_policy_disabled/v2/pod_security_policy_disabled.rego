package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.pod_security_policy_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

pod_security_policy_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not resource.pod_security_policy_config
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'pod_security_policy_config' is undefined", "keyExpectedValue": "Attribute 'pod_security_policy_config' should be defined", "remediation": "pod_security_policy_config {\n\t\tenabled = true\n\t}\n", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], [])}
}

pod_security_policy_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.pod_security_policy_config
	resource.pod_security_policy_config.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'enabled' of 'pod_security_policy_config' is false", "keyExpectedValue": "Attribute 'enabled' of 'pod_security_policy_config' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].pod_security_policy_config.enabled", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], ["pod_security_policy_config", "enabled"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Pod Security Policy Disabled"
# description: >-
#   Kubernetes Clusters must have Pod Security Policy controller enabled, which means there must be a 'pod_security_policy_config' with the 'enabled' attribute equal to true
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.pod_security_policy_disabled"
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
#       identifier: google_container_cluster
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
pod_security_policy_disabled_snippet[violation] {
	pod_security_policy_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

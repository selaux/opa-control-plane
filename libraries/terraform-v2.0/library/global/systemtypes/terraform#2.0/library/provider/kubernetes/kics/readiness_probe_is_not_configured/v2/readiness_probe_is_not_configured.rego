package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.readiness_probe_is_not_configured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

readiness_probe_is_not_configured_inner[result] {
	resource := input.document[i].resource[resourceType]
	not resource_equal(resourceType)
	specInfo := tf_lib.getSpecInfo(resource[name])
	container := specInfo.spec[types[x]]
	is_object(container) == true
	not common_lib.valid_key(container, "readiness_probe")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.readiness_probe is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.readiness_probe should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

readiness_probe_is_not_configured_inner[result] {
	resource := input.document[i].resource[resourceType]
	not resource_equal(resourceType)
	specInfo := tf_lib.getSpecInfo(resource[name])
	container := specInfo.spec[types[x]]
	is_array(container) == true
	containersType := container[_]
	not common_lib.valid_key(containersType, "readiness_probe")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].readiness_probe is undefined", [resourceType, name, specInfo.path, types[x], containersType]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].readiness_probe should be set", [resourceType, name, specInfo.path, types[x], containersType]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

resource_equal(type) {
	resources := {"kubernetes_cron_job", "kubernetes_job"}

	type == resources[_]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Readiness Probe Is Not Configured"
# description: >-
#   Check if Readiness Probe is not configured.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.readiness_probe_is_not_configured"
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
readiness_probe_is_not_configured_snippet[violation] {
	readiness_probe_is_not_configured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

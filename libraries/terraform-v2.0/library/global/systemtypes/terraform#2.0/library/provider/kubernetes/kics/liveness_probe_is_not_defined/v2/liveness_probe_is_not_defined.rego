package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.liveness_probe_is_not_defined.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

liveness_probe_is_not_defined_inner[result] {
	types := {"kubernetes_deployment": "spec.template.spec.container", "kubernetes_pod": "spec.container"}
	resource_prefix := types[x]
	resource := input.document[i].resource[x][name]
	path := checkPath(resource)
	not common_lib.valid_key(path, "liveness_probe")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'livenessProbe' is undefined or null", "keyExpectedValue": "Attribute 'livenessProbe' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": x, "searchKey": sprintf("%s[%s].%s", [x, name, resource_prefix])}
}

checkPath(resource) = path {
	path := resource.spec.template.spec.container
} else = path {
	path := resource.spec.container
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Liveness Probe Is Not Defined"
# description: >-
#   In case of an unresponsive container, a Liveness Probe can help your application become more available since it restarts the container. However, it can lead to cascading failures. Define one if you really need it
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.liveness_probe_is_not_defined"
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
liveness_probe_is_not_defined_snippet[violation] {
	liveness_probe_is_not_defined_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

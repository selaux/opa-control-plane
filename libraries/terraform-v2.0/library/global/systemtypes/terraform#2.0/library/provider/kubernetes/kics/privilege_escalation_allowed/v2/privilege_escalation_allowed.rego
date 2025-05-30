package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.privilege_escalation_allowed.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

privilege_escalation_allowed_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containers[y].security_context.allow_privilege_escalation == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].security_context.allow_privilege_escalation is set to true", [resourceType, name, specInfo.path, types[x], y]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context.allow_privilege_escalation should not be set to true", [resourceType, name, specInfo.path, types[x], y]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.name={{%s}}.security_context.allow_privilege_escalation", [resourceType, name, specInfo.path, types[x], containers[y].name]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x], "security_context", "allow_privilege_escalation"])}
}

privilege_escalation_allowed_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	containers.security_context.allow_privilege_escalation == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.security_context.allow_privilege_escalation is set to true", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context.allow_privilege_escalation should not be set to true", [resourceType, name, specInfo.path, types[x]]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.security_context.allow_privilege_escalation", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x], "security_context", "allow_privilege_escalation"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Privilege Escalation Allowed"
# description: >-
#   Containers should not run with allowPrivilegeEscalation in order to prevent them from gaining more privileges than their parent process
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.privilege_escalation_allowed"
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
privilege_escalation_allowed_snippet[violation] {
	privilege_escalation_allowed_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

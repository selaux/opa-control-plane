package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.secrets_as_environment_variables.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

secrets_as_environment_variables_inner[result] {
	resource := input.document[i].resource[resourceType][name]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	has_secret_key_ref(containers[y])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].env.value_from.secret_key_ref is set", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].env.value_from.secret_key_ref should be undefined", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

secrets_as_environment_variables_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	has_secret_key_ref(containers)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.env.value_from.secret_key_ref is set", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.env.value_from.secret_key_ref should be undefined", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.env", [resourceType, name, specInfo.path, types[x]])}
}

secrets_as_environment_variables_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	has_secret_key_ref(containers[y])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].env_from.secret_ref is set", [resourceType, name, specInfo.path, types[x], y]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].env_from.secret_ref should be undefined", [resourceType, name, specInfo.path, types[x], y]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

secrets_as_environment_variables_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	has_secret_key_ref(containers)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.env_from.secret_ref is set", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.env_from.secret_ref should be undefined", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.env_from", [resourceType, name, specInfo.path, types[x]])}
}

has_secret_key_ref(container) {
	is_array(container.env) == true

	common_lib.valid_key(container.env[x].value_from, "secret_key_ref")
}

has_secret_key_ref(container) {
	is_object(container.env) == true

	common_lib.valid_key(container.env.value_from, "secret_key_ref")
}

has_secret_key_ref(container) {
	is_array(container.env) == true

	common_lib.valid_key(container.env_from, "secret_ref")
}

has_secret_key_ref(container) {
	is_object(container.env) == true

	common_lib.valid_key(container.env_from, "secret_ref")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Secrets As Environment Variables"
# description: >-
#   Container should not use secrets as environment variables
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.secrets_as_environment_variables"
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
secrets_as_environment_variables_snippet[violation] {
	secrets_as_environment_variables_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

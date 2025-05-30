package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.permissive_access_to_create_pods.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

create := "create"

resourceTypes := ["kubernetes_role", "kubernetes_cluster_role"]

pods := "pods"

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	resource.rule[ru].verbs[l] == create
	resource.rule[ru].resources[r] == pods
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contains the value 'create' and %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain the value 'create' when %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, create])}
}

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	resource.rule[ru].verbs[l] == create
	isWildCardValue(resource.rule[ru].resources[r])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contains the value 'create' and %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain the value 'create' when %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, create])}
}

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	isWildCardValue(resource.rule[ru].verbs[l])
	resource.rule[ru].resources[r] == pods
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contains a wildcard value and %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain a wildcard value when %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, resource.rule[ru].verbs[l]])}
}

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	isWildCardValue(resource.rule[ru].verbs[l])
	isWildCardValue(resource.rule[ru].resources[r])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contains a wildcard value and %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain a wildcard value when %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, resource.rule[ru].verbs[l]])}
}

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	resource.rule.verbs[l] == create
	resource.rule.resources[r] == pods
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contains the value 'create' and %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain the value 'create' when %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, create])}
}

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	resource.rule.verbs[l] == create
	isWildCardValue(resource.rule.resources[r])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contains the value 'create' and %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain the value 'create' when %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, create])}
}

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	isWildCardValue(resource.rule.verbs[l])
	resource.rule.resources[r] == pods
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verb contains a wildcard value and %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verb should not contain a wildcard value when %s[%s].rule.resources contains the value 'pods'", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, resource.rule.verbs[l]])}
}

permissive_access_to_create_pods_inner[result] {
	resource := input.document[i].resource[resourceTypes[t]][name]
	isWildCardValue(resource.rule.verbs[l])
	isWildCardValue(resource.rule.resources[r])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contains a wildcard value and %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain a wildcard value when %s[%s].rule.resources contains a wildcard value", [resourceTypes[t], name, resourceTypes[t], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule.verbs.%s", [resourceTypes[t], name, resource.rule.verbs[l]])}
}

isWildCardValue(val) {
	regex.match(".*\\*.*", val)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Permissive Access to Create Pods"
# description: >-
#   The permission to create pods in a cluster should be restricted because it allows privilege escalation.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.permissive_access_to_create_pods"
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
permissive_access_to_create_pods_snippet[violation] {
	permissive_access_to_create_pods_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

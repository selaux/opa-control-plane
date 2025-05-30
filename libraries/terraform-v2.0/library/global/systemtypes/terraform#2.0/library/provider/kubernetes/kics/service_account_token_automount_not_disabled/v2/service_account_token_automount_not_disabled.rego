package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.service_account_token_automount_not_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

service_account_token_automount_not_disabled_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	not common_lib.valid_key(resource.spec, "automount_service_account_token")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_pod[%s].spec.automount_service_account_token is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_pod[%s].spec.automount_service_account_token should be set", [name]), "remediation": "automount_service_account_token = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_pod", name, "spec"], [])}
}

service_account_token_automount_not_disabled_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	resource.spec.automount_service_account_token == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod[%s].spec.automount_service_account_token is set to true", [name]), "keyExpectedValue": sprintf("kubernetes_pod[%s].spec.automount_service_account_token should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec.automount_service_account_token", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_pod", name, "spec"], ["automount_service_account_token"])}
}

listKinds := {"kubernetes_deployment", "kubernetes_daemonset", "kubernetes_job", "kubernetes_stateful_set", "kubernetes_replication_controller"}

service_account_token_automount_not_disabled_inner[result] {
	resource := input.document[i].resource
	k8 := resource[listKinds[x]][name].spec.template.spec
	not common_lib.valid_key(k8, "automount_service_account_token")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].spec.template.spec.automount_service_account_token is undefined", [listKinds[x], name]), "keyExpectedValue": sprintf("%s[%s].spec.template.spec.automount_service_account_token should be set", [listKinds[x], name]), "remediation": "automount_service_account_token = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": listKinds[x], "searchKey": sprintf("%s[%s].spec.template.spec", [listKinds[x], name]), "searchLine": common_lib.build_search_line(["resource", listKinds[x], name, "spec", "template", "spec"], [])}
}

service_account_token_automount_not_disabled_inner[result] {
	resource := input.document[i].resource
	resource[listKinds[x]][name].spec.template.spec.automount_service_account_token == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].spec.template.spec.automount_service_account_token is set to true", [listKinds[x], name]), "keyExpectedValue": sprintf("%s[%s].spec.template.spec.automount_service_account_token should be set to false", [listKinds[x], name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": listKinds[x], "searchKey": sprintf("%s[%s].spec.template.spec.automount_service_account_token", [listKinds[x], name]), "searchLine": common_lib.build_search_line(["resource", listKinds[x], name, "spec", "template", "spec"], ["automount_service_account_token"])}
}

service_account_token_automount_not_disabled_inner[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	not common_lib.valid_key(resource.spec.jobTemplate.spec.template.spec, "automount_service_account_token")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.automount_service_account_token is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.automount_service_account_token should be set", [name]), "remediation": "automount_service_account_token = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cron_job", "searchKey": sprintf("kubernetes_cron_job[%s].spec.jobTemplate.spec.template.spec", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_cron_job", name, "spec", "template", "spec", "template", "spec"], [])}
}

service_account_token_automount_not_disabled_inner[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	resource.spec.job_template.spec.template.spec.automount_service_account_token == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.automount_service_account_token is set to true", [name]), "keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.automount_service_account_token should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cron_job", "searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.automount_service_account_token", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_cron_job", name, "spec", "template", "spec", "template", "spec"], ["automount_service_account_token"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Service Account Token Automount Not Disabled"
# description: >-
#   Service Account Tokens are automatically mounted even if not necessary
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.service_account_token_automount_not_disabled"
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
service_account_token_automount_not_disabled_snippet[violation] {
	service_account_token_automount_not_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

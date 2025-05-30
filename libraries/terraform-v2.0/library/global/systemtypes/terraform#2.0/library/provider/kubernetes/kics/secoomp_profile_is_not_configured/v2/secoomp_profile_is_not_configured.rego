package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.secoomp_profile_is_not_configured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

#pod
secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	not common_lib.valid_key(annotations, "${seccomp.security.alpha.kubernetes.io/defaultProfileName}")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].metadata.annotations", [name])}
}

secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	common_lib.valid_key(annotations, "${seccomp.security.alpha.kubernetes.io/defaultProfileName}")
	seccomp := annotations["${seccomp.security.alpha.kubernetes.io/defaultProfileName}"]
	seccomp != "runtime/default"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is '%s'", [name, seccomp]), "keyExpectedValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is 'runtime/default'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].metadata.annotations", [name])}
}

secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	not common_lib.valid_key(metadata, "annotations")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_pod[%s].metadata.annotations is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_pod[%s].metadata.annotations should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].metadata", [name])}
}

# cron_job
secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	metadata := resource.spec.job_template.spec.template.metadata
	not common_lib.valid_key(metadata, "annotations")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cron_job", "searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata", [name])}
}

secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	metadata := resource.spec.job_template.spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	not common_lib.valid_key(annotations, "${seccomp.security.alpha.kubernetes.io/defaultProfileName}")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cron_job", "searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations", [name])}
}

secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	metadata := resource.spec.job_template.spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	common_lib.valid_key(annotations, "${seccomp.security.alpha.kubernetes.io/defaultProfileName}")
	seccomp := annotations["${seccomp.security.alpha.kubernetes.io/defaultProfileName}"]
	seccomp != "runtime/default"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is '%s'", [name, seccomp]), "keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is 'runtime/default'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cron_job", "searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations", [name])}
}

#general
resources := {"kubernetes_cron_job", "kubernetes_pod"}

secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource[resourceType]
	resourceType != resources[x]
	metadata := resource[name].spec.template.metadata
	not common_lib.valid_key(metadata, "annotations")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].spec.template.metadata.annotations is undefined", [resourceType, name]), "keyExpectedValue": sprintf("%s[%s].spec.template.metadata.annotations should be set", [resourceType, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.template.metadata", [resourceType, name])}
}

secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource[resourceType]
	resourceType != resources[x]
	metadata := resource[name].spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	not common_lib.valid_key(annotations, "${seccomp.security.alpha.kubernetes.io/defaultProfileName}")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is undefined", [resourceType, name]), "keyExpectedValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName should be set", [resourceType, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.template.metadata.annotations", [resourceType, name])}
}

secoomp_profile_is_not_configured_inner[result] {
	resource := input.document[i].resource[resourceType]
	resourceType != resources[x]
	metadata := resource[name].spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	common_lib.valid_key(annotations, "${seccomp.security.alpha.kubernetes.io/defaultProfileName}")
	seccomp := annotations["${seccomp.security.alpha.kubernetes.io/defaultProfileName}"]
	seccomp != "runtime/default"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is '%s'", [resourceType, name, seccomp]), "keyExpectedValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is 'runtime/default'", [resourceType, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.template.metadata.annotations", [resourceType, name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Seccomp Profile Is Not Configured"
# description: >-
#   Containers should be configured with a secure Seccomp profile to restrict potentially dangerous syscalls
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.secoomp_profile_is_not_configured"
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
secoomp_profile_is_not_configured_snippet[violation] {
	secoomp_profile_is_not_configured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

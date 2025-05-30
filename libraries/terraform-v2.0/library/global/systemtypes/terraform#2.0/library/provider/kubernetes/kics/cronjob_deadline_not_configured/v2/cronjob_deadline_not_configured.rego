package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.cronjob_deadline_not_configured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

cronjob_deadline_not_configured_inner[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	not common_lib.valid_key(resource.spec, "starting_deadline_seconds")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_cron_job[%s].spec.starting_deadline_seconds is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.starting_deadline_seconds should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cron_job", "searchKey": sprintf("kubernetes_cron_job[%s].spec", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CronJob Deadline Not Configured"
# description: >-
#   Cronjobs must have a configured deadline, which means the attribute 'starting_deadline_seconds' must be defined
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.cronjob_deadline_not_configured"
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
cronjob_deadline_not_configured_snippet[violation] {
	cronjob_deadline_not_configured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

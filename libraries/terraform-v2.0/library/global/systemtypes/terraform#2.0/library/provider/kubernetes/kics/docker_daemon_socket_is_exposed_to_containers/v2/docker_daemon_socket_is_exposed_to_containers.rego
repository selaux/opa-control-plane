package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.docker_daemon_socket_is_exposed_to_containers.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

docker_daemon_socket_is_exposed_to_containers_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	volumes := resource.spec.volume
	volumes[c].host_path.path == "/var/run/docker.sock"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("spec.volume[%d].host_path.path is '/var/run/docker.sock'", [c]), "keyExpectedValue": sprintf("spec.volume[%d].host_path.path should not be '/var/run/docker.sock'", [c]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec.volume", [name])}
}

docker_daemon_socket_is_exposed_to_containers_inner[result] {
	resource := input.document[i].resource
	listKinds := {"kubernetes_daemonset", "kubernetes_deployment", "kubernetes_job", "kubernetes_replication_controller", "kubernetes_stateful_set"}
	kind := listKinds[x]
	common_lib.valid_key(resource, kind)
	workload := resource[kind][name]
	spec := workload.spec.template.spec
	volumes := spec.volume
	volumes[c].host_path.path == "/var/run/docker.sock"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("spec.template.spec.volume[%d].host_path.path is '/var/run/docker.sock'", [c]), "keyExpectedValue": sprintf("spec.template.spec.volume[%d].host_path.path should not be '/var/run/docker.sock'", [c]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": kind, "searchKey": sprintf("%s[%s].spec.template.spec.volume", [kind, name])}
}

docker_daemon_socket_is_exposed_to_containers_inner[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	spec := resource.spec.job_template.spec.template.spec
	volumes := spec.volume
	volumes[c].host_path.path == "/var/run/docker.sock"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("spec.job_template.spec.template.spec.volume[%d].host_path.path is '/var/run/docker.sock'", [c]), "keyExpectedValue": sprintf("spec.job_template.spec.template.spec.volume[%d].host_path.path should not be '/var/run/docker.sock'", [c]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cron_job", "searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.volume", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Docker Daemon Socket is Exposed to Containers"
# description: >-
#   Sees if Docker Daemon Socket is not exposed to Containers
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.docker_daemon_socket_is_exposed_to_containers"
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
docker_daemon_socket_is_exposed_to_containers_snippet[violation] {
	docker_daemon_socket_is_exposed_to_containers_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

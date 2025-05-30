package global.systemtypes["terraform:2.0"].library.provider.gcp.storage.versioning.v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "GCP: Storage Bucket: Prohibit buckets without versioning"
# description: >-
#   Requires versioning to be enabled for google_storage_bucket resource.
# severity: "medium"
# platform: "terraform"
# resource-type: "gcp-storage_bucket"
# custom:
#   id: "gcp.storage.versioning"
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
#       max: "v0.13"
#   provider:
#     name: google
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - { scope: "resource", service: "storage", name: "bucket", identifier: "google_storage_bucket", argument: "versioning.enabled" }
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
prohibit_bucket_without_versioning[violation] {
	resource := util.storage_bucket_resource_changes[_]
	decision := unversioned_bucket(resource)

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, resource, decision.context),
	}
}

unversioned_bucket(resource) := obj(resource) {
	not resource.change.after.versioning
}

unversioned_bucket(resource) := obj(resource) {
	resource.change.after.versioning == []
}

unversioned_bucket(resource) := obj(resource) {
	versioning := resource.change.after.versioning[_]
	versioning.enabled == false
}

obj(resource) := {
	"message": sprintf("Storage Bucket %v without versioning is prohibited.", [resource.address]),
	"resource": resource,
	"context": {"versioning.enabled": false},
}

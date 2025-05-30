package global.systemtypes["terraform:2.0"].library.provider.gcp.database.authorization.v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "GCP: BigQuery Dataset: Prohibit Dataset accessible to all authenticated users"
# description: "Restrict public accessibilty to BigQuery Datasets"
# severity: "medium"
# platform: "terraform"
# resource-type: "gcp-bigquery_dataset"
# custom:
#   id: "gcp.database.authorization"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - { scope: "resource", service: "bigquery", name: "dataset", identifier: "google_bigquery_dataset", argument: "access.special_group" }
#     - { scope: "resource", service: "bigquery", name: "dataset_access", identifier: "google_bigquery_dataset_access", argument: "special_group" }
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
prohibit_dataset_with_allauthenticatedusers_access[violation] {
	allauthenticatedusers_access[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

allauthenticatedusers_access[violation] {
	resource := util.bigquery_dataset_resource_changes[_]
	special_group := resource.change.after.access[_].special_group
	special_group == "allAuthenticatedUsers"

	violation := {
		"message": sprintf("Big Query Dataset %v has prohibited access 'allAuthenticatedUsers'.", [resource.address]),
		"resource": resource,
		"context": {"access.special_group": special_group},
	}
}

allauthenticatedusers_access[violation] {
	resource := util.bigquery_dataset_access_resource_changes[_]
	special_group := resource.change.after.special_group
	special_group == "allAuthenticatedUsers"

	violation := {
		"message": sprintf("Big Query Dataset %v has prohibited access 'allAuthenticatedUsers'.", [resource.address]),
		"resource": resource,
		"context": {"special_group": special_group},
	}
}

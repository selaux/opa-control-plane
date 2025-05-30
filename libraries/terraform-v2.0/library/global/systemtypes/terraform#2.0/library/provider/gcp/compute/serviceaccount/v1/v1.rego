package global.systemtypes["terraform:2.0"].library.provider.gcp.compute.serviceaccount.v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "GCP: Service Account: Prohibit using default Service Account"
# description: "Requires custom service account."
# severity: "medium"
# platform: "terraform"
# resource-type: "gcp-service_account"
# custom:
#   id: "gcp.compute.serviceaccount"
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
#     - { scope: "resource", service: "compute", name: "instance", identifier: "google_compute_instance", argument: "service_account.email" }
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
prohibit_default_service_account[violation] {
	incorrect_service_account[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

incorrect_service_account[violation] {
	resource := util.compute_instance_resource_changes[_]
	resource.change.after.service_account == []

	violation := {
		"message": sprintf("Compute Instance %v does not have a service account set.", [resource.address]),
		"resource": resource,
		"context": {"service_account": []},
	}
}

incorrect_service_account[violation] {
	resource := util.compute_instance_resource_changes[_]
	service_account := resource.change.after.service_account[_]
	not service_account.email

	violation := {
		"message": sprintf("Compute Instance %v is missing a service account email.", [resource.address]),
		"resource": resource,
		"context": {"service_account.email": null},
	}
}

incorrect_service_account[violation] {
	resource := util.compute_instance_resource_changes[_]
	email := resource.change.after.service_account[_].email
	endswith(email, "@developer.gserviceaccount.com")

	violation := {
		"message": sprintf("Compute Instance %v with default service account %v is not allowed.", [resource.address, email]),
		"resource": resource,
		"context": {"service_account.email": email},
	}
}

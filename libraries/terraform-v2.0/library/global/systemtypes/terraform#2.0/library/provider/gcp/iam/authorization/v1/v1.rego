package global.systemtypes["terraform:2.0"].library.provider.gcp.iam.authorization.v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import future.keywords.in

# METADATA: library-snippet
# version: v1
# title: "GCP: IAM: Prohibit service account with admin privileges"
# description: "Restrict service account to have admin privileges"
# severity: "medium"
# platform: "terraform"
# resource-type: "gcp-iam"
# custom:
#   id: "gcp.iam.authorization"
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
#     - { scope: "resource", service: "project", name: "iam_member", identifier: "google_project_iam_member", argument: "role" }
#     - { scope: "resource", service: "project", name: "iam_member", identifier: "google_project_iam_member", argument: "member" }
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
prohibit_service_account_with_admin_privileges[violation] {
	incorrect_iam_member[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

incorrect_iam_member[violation] {
	resource := util.project_iam_member_resource_changes[_]
	role := resource.change.after.role
	member := resource.change.after.member
	is_admin(role, member)

	violation := {
		"message": sprintf("IAM Member %v has default service account %v attached with a prohibited admin access %v.", [resource.address, member, role]),
		"resource": resource,
		"context": {"role": role, "member": member},
	}
}

is_admin(resource_role, resource_email) {
	resource_role in ["roles/owner", "roles/editor"]
	endswith(resource_email, ".gserviceaccount.com")
}

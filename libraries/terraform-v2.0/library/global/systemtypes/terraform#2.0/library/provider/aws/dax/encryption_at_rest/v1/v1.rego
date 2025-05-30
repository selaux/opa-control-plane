package global.systemtypes["terraform:2.0"].library.provider.aws.dax.encryption_at_rest.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: DAX: Prohibit DAX clusters with disabled encryption at rest"
# description: Require AWS/DAX clusters to have enabled encryption at rest.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-dax"
# custom:
#   id: "aws.dax.encryption_at_rest"
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
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - { scope: "resource", service: "dax", name: "dax_cluster", identifier: "aws_dax_cluster", argument: "server_side_encryption.enabled" }
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
prohibit_dax_clusters_with_disabled_encryption_at_rest[violation] {
	insecure_dax_cluster[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_dax_cluster[obj] {
	dax_cluster := util.dax_cluster_resource_changes[_]
	utils.is_key_defined(dax_cluster.change.after, "server_side_encryption")
	dax_cluster.change.after.server_side_encryption[_].enabled == false

	obj := {
		"message": sprintf("AWS DAX cluster %v with 'server_side_encryption' disabled is prohibited.", [dax_cluster.address]),
		"resource": dax_cluster,
		"context": {"server_side_encryption.enabled": dax_cluster.change.after.server_side_encryption[_].enabled},
	}
}

insecure_dax_cluster[obj] {
	dax_cluster := util.dax_cluster_resource_changes[_]
	not utils.is_key_defined(dax_cluster.change.after, "server_side_encryption")

	obj := {
		"message": sprintf("AWS DAX cluster %v is missing the 'server_side_encryption' configuration.", [dax_cluster.address]),
		"resource": dax_cluster,
		"context": {"server_side_encryption": "undefined"},
	}
}

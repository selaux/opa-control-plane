package global.systemtypes["terraform:2.0"].library.provider.aws.redshift.publicly_accessible.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Redshift: Prohibit publicly accessible Redshift cluster"
# description: Require AWS/Redshift cluster to not be publicly accessible.
# severity: "critical"
# platform: "terraform"
# resource-type: "aws-redshift"
# custom:
#   id: "aws.redshift.publicly_accessible"
#   impact: ""
#   remediation: ""
#   severity: "critical"
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
#     - { scope: "resource", service: "redshift", name: "redshift_cluster", identifier: "aws_redshift_cluster", argument: "publicly_accessible" }
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
prohibit_publicly_accessible_redshift_cluster[violation] {
	insecure_redshift_cluster[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_redshift_cluster[obj] {
	redshift_cluster := util.redshift_cluster_resource_changes[_]
	utils.is_key_defined(redshift_cluster.change.after, "publicly_accessible")
	redshift_cluster.change.after.publicly_accessible == true

	obj := {
		"message": sprintf("Publicly accessible Redshift cluster %v is prohibited.", [redshift_cluster.address]),
		"resource": redshift_cluster,
		"context": {"publicly_accessible": redshift_cluster.change.after.publicly_accessible},
	}
}

insecure_redshift_cluster[obj] {
	redshift_cluster := util.redshift_cluster_resource_changes[_]
	not utils.is_key_defined(redshift_cluster.change.after, "publicly_accessible")

	obj := {
		"message": sprintf("Redshift cluster %v does not have publicly_accessible specified and is publicly accessible by default", [redshift_cluster.address]),
		"resource": redshift_cluster,
		"context": {"publicly_accessible": "undefined"},
	}
}

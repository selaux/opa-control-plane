package global.systemtypes["terraform:2.0"].library.provider.aws.dms.publicly_accessible.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: DMS: Prohibit publicly accessible DMS replication instances"
# description: Require AWS/DMS replication instances to not be publicly accessible.
# severity: "critical"
# platform: "terraform"
# resource-type: "aws-dms"
# custom:
#   id: "aws.dms.publicly_accessible"
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
#     - { scope: "resource", service: "dms", name: "replication_instance", identifier: "aws_dms_replication_instance", argument: "publicly_accessible" }
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
prohibit_publicly_accessible_dms_replication_instance[violation] {
	insecure_dms_replication_instance[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_dms_replication_instance[obj] {
	dms_replication_instance := util.dms_replication_instance_resource_changes[_]
	dms_replication_instance.change.after.publicly_accessible == true

	obj := {
		"message": sprintf("Publicly accessible DMS Replication instance %v is prohibited.", [dms_replication_instance.address]),
		"resource": dms_replication_instance,
		"context": {"publicly_accessible": dms_replication_instance.change.after.publicly_accessible},
	}
}

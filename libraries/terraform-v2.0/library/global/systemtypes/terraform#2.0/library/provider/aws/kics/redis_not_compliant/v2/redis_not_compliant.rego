package global.systemtypes["terraform:2.0"].library.provider.aws.kics.redis_not_compliant.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

redis_not_compliant_inner[result] {
	resource := input.document[i].resource.aws_elasticache_cluster[name]
	min_version_string := "4.0.10"
	eval_version_number(resource.engine_version) < eval_version_number(min_version_string)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_elasticache_cluster[%s].engine_version isn't compliant with the requirements", [name]), "keyExpectedValue": sprintf("aws_elasticache_cluster[%s].engine_version should be compliant with the requirements", [name]), "resourceName": tf_lib.get_specific_resource_name(resource, "aws_elasticache_cluster", name), "resourceType": "aws_elasticache_cluster", "searchKey": sprintf("aws_elasticache_cluster[%s].engine_version", [name])}
}

eval_version_number(engine_version) = numeric_version {
	version := split(engine_version, ".")
	numeric_version := ((to_number(version[0]) * 100) + (to_number(version[1]) * 10)) + to_number(version[2])
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redis Not Compliant"
# description: >-
#   Check if the redis version is compliant with the necessary AWS PCI DSS requirements
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.redis_not_compliant"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
#     - argument: ""
#       identifier: aws_elasticache_cluster
#       name: ""
#       scope: resource
#       service: ""
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
redis_not_compliant_snippet[violation] {
	redis_not_compliant_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.config_rule_for_encrypted_volumes_is_disabled.v2

config_rule_for_encrypted_volumes_is_disabled_inner[result] {
	resource := input.document[i].resource
	config := resource.aws_config_config_rule
	not checkSource(config, "ENCRYPTED_VOLUMES")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "No 'aws_config_config_rule' resource has source id: 'ENCRYPTED_VOLUMES'", "keyExpectedValue": "There should be a 'aws_config_config_rule' resource with source id: 'ENCRYPTED_VOLUMES'", "resourceName": "unknown", "resourceType": "aws_config_config_rule", "searchKey": "aws_config_config_rule"}
	#refer to the first rule

}

checkSource(config_rules, expected_source) {
	source := config_rules[_].source
	source.source_identifier == expected_source
} else = false

# METADATA: library-snippet
# version: v1
# title: "KICS: Config Rule For Encrypted Volumes Disabled"
# description: >-
#   Check if AWS config rules do not identify Encrypted Volumes as a source.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.config_rule_for_encrypted_volumes_is_disabled"
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
#     - argument: ""
#       identifier: aws_config_config_rule
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
config_rule_for_encrypted_volumes_is_disabled_snippet[violation] {
	config_rule_for_encrypted_volumes_is_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

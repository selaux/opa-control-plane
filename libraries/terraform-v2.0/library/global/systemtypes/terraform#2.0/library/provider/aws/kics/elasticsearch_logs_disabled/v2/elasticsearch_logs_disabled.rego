package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticsearch_logs_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticsearch_logs_disabled_inner[result] {
	awsElasticsearchDomain := input.document[i].resource.aws_elasticsearch_domain[name]
	not common_lib.valid_key(awsElasticsearchDomain, "log_publishing_options")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'log_publishing_options' is undefined or null", "keyExpectedValue": "'log_publishing_options' should be defined and not null", "remediation": "log_publishing_options {\n\t\t enabled = true \n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(awsElasticsearchDomain, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[{{%s}}]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name], [])}
}

elasticsearch_logs_disabled_inner[result] {
	awsElasticsearchDomain := input.document[i].resource.aws_elasticsearch_domain[name]
	awsElasticsearchDomain.log_publishing_options.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'log_publishing_options.enabled' is false", "keyExpectedValue": "'log_publishing_options.enabled' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(awsElasticsearchDomain, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[{{%s}}].log_publishing_options.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name, "log_publishing_options", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Elasticsearch Log Disabled"
# description: >-
#   AWS Elasticsearch should have logs enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticsearch_logs_disabled"
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
#       identifier: aws_elasticsearch_domain
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
elasticsearch_logs_disabled_snippet[violation] {
	elasticsearch_logs_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

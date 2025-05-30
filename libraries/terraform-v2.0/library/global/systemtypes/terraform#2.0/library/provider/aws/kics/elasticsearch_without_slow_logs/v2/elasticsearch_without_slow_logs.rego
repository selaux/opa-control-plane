package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticsearch_without_slow_logs.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticsearch_without_slow_logs_inner[result] {
	awsElasticsearchDomain := input.document[i].resource.aws_elasticsearch_domain[name]
	logType := awsElasticsearchDomain.log_publishing_options.log_type
	not commonLib.inArray(["INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS"], logType)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'log_publishing_options.enabled' is ES_APPLICATION_LOGS or AUDIT_LOGS", "keyExpectedValue": "'log_publishing_options.log_type' should not be INDEX_SLOW_LOGS or SEARCH_SLOW_LOGS  ", "remediation": json.marshal({"after": "INDEX_SLOW_LOGS", "before": sprintf("%s", [logType])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(awsElasticsearchDomain, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[{{%s}}].log_publishing_options.log_type", [name]), "searchLine": commonLib.build_search_line(["resource", "aws_elasticsearch_domain", name, "log_publishing_options", "log_type"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ElasticSearch Without Slow Logs"
# description: >-
#   Ensure that AWS Elasticsearch enables support for slow logs
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticsearch_without_slow_logs"
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
elasticsearch_without_slow_logs_snippet[violation] {
	elasticsearch_without_slow_logs_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

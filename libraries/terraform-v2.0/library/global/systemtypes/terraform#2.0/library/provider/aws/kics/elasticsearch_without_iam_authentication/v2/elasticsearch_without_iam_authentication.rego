package global.systemtypes["terraform:2.0"].library.provider.aws.kics.elasticsearch_without_iam_authentication.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

elasticsearch_without_iam_authentication_inner[result] {
	resource := input.document[i].resource.aws_elasticsearch_domain[name]
	not has_policy(name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Elasticsearch Domain does not have a policy associated", "keyExpectedValue": "Elasticsearch Domain has a policy associated", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name], [])}
}

elasticsearch_without_iam_authentication_inner[result] {
	resource := input.document[i].resource.aws_elasticsearch_domain[name]
	without_iam_auth(name)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Elasticsearch Domain does not ensure IAM Authentication", "keyExpectedValue": "Elasticsearch Domain ensure IAM Authentication", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_elasticsearch_domain", "searchKey": sprintf("aws_elasticsearch_domain[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name], [])}
}

has_policy(name) {
	policy := input.document[i].resource.aws_elasticsearch_domain_policy[_]
	split(policy.domain_name, ".")[1] == name
}

without_iam_auth(name) {
	policy := input.document[i].resource.aws_elasticsearch_domain_policy[_]
	split(policy.domain_name, ".")[1] == name

	p := common_lib.json_unmarshal(policy.access_policies)
	st := p.Statement[_]
	st.Effect == "Allow"
	common_lib.any_principal(st)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Elasticsearch Without IAM Authentication"
# description: >-
#   AWS Elasticsearch should ensure IAM Authentication
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.elasticsearch_without_iam_authentication"
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
elasticsearch_without_iam_authentication_snippet[violation] {
	elasticsearch_without_iam_authentication_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

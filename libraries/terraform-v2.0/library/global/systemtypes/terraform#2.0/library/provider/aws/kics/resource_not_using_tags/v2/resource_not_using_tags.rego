package global.systemtypes["terraform:2.0"].library.provider.aws.kics.resource_not_using_tags.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

resource_not_using_tags_inner[result] {
	resource := input.document[i].resource[res][name]
	tf_lib.check_resource_tags(res)
	check_default_tags == false
	not common_lib.valid_key(resource, "tags")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[{{%s}}].tags is undefined or null", [res, name]), "keyExpectedValue": sprintf("%s[{{%s}}].tags should be defined and not null", [res, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": res, "searchKey": sprintf("%s[{{%s}}]", [res, name])}
}

resource_not_using_tags_inner[result] {
	resource := input.document[i].resource[res][name]
	tf_lib.check_resource_tags(res)
	check_default_tags == false
	not check_different_tag(resource.tags)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[{{%s}}].tags does not have additional tags defined other than 'Name'", [res, name]), "keyExpectedValue": sprintf("%s[{{%s}}].tags has additional tags defined other than 'Name'", [res, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": res, "searchKey": sprintf("%s[{{%s}}].tags", [res, name])}
}

check_different_tag(tags) {
	tags[x]
	x != "Name"
}

check_default_tags {
	common_lib.valid_key(input.document[_].provider.aws.default_tags, "tags")
} else {
	common_lib.valid_key(input.document[_].provider.aws[_].default_tags, "tags")
} else = false

# METADATA: library-snippet
# version: v1
# title: "KICS: Resource Not Using Tags"
# description: >-
#   AWS services resource tags are an essential part of managing components. As a best practice, the field 'tags' should have additional tags defined other than 'Name'
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.resource_not_using_tags"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
#       identifier: aws_acm_certificate
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
resource_not_using_tags_snippet[violation] {
	resource_not_using_tags_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ec2_instance_monitoring_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ec2_instance_monitoring_disabled_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	not common_lib.valid_key(resource, "monitoring")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'monitoring' is undefined or null", [name]), "keyExpectedValue": sprintf("'monitoring' should be defined and not null", [name]), "remediation": "monitoring = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance.{{%s}}", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name], [])}
}

ec2_instance_monitoring_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "monitoring")
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'monitoring' is undefined or null", [name]), "keyExpectedValue": sprintf("'monitoring' should be defined and not null", [name]), "remediation": sprintf("%s = true", [keyToCheck]), "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

ec2_instance_monitoring_disabled_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	resource.monitoring == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'monitoring' is set to false", [name]), "keyExpectedValue": sprintf("'monitoring' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance.{{%s}}.monitoring", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "monitoring"], [])}
}

ec2_instance_monitoring_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "monitoring")
	module[keyToCheck] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'monitoring' is set to false", [name]), "keyExpectedValue": sprintf("'monitoring' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EC2 Instance Monitoring Disabled"
# description: >-
#   EC2 Instance should have detailed monitoring enabled. With detailed monitoring enabled data is available in 1-minute periods
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ec2_instance_monitoring_disabled"
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
#       identifier: aws_instance
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
ec2_instance_monitoring_disabled_snippet[violation] {
	ec2_instance_monitoring_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

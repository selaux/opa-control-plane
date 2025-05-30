package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ec2_not_ebs_optimized.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ec2_not_ebs_optimized_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	instanceType := get_instance_type(resource, "instance_type")
	not common_lib.is_aws_ebs_optimized_by_default(instanceType)
	resource.ebs_optimized == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'ebs_optimized' is set to false", "keyExpectedValue": "'ebs_optimized' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[{{%s}}].ebs_optimized", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "ebs_optimized"], [])}
}

ec2_not_ebs_optimized_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "ebs_optimized")
	instanceTypeKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "instance_type")
	instanceType := get_instance_type(module, instanceTypeKey)
	not common_lib.is_aws_ebs_optimized_by_default(instanceType)
	module[keyToCheck] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'ebs_optimized' is set to false", "keyExpectedValue": "'ebs_optimized' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].ebs_optimized", [name]), "searchLine": common_lib.build_search_line(["module", name, "ebs_optimized"], [])}
}

ec2_not_ebs_optimized_inner[result] {
	resource := input.document[i].resource.aws_instance[name]
	instanceType := get_instance_type(resource, "instance_type")
	not common_lib.is_aws_ebs_optimized_by_default(instanceType)
	not common_lib.valid_key(resource, "ebs_optimized")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'ebs_optimized' is undefined or null", "keyExpectedValue": "'ebs_optimized' should be set to true", "remediation": "ebs_optimized = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[{{%s}}]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name], [])}
}

ec2_not_ebs_optimized_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "ebs_optimized")
	instanceTypeKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "instance_type")
	instanceType := get_instance_type(module, instanceTypeKey)
	not common_lib.is_aws_ebs_optimized_by_default(instanceType)
	not common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'ebs_optimized' is undefined or null", "keyExpectedValue": "'ebs_optimized' should be set to true", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# Since terraform does not provide a default value for instance_type, we use the default value defined on cloud formation
get_instance_type(instanceProperties, instanceKey) = result {
	common_lib.valid_key(instanceProperties, instanceKey)
	result = instanceProperties[instanceKey]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EC2 Not EBS Optimized"
# description: >-
#   It's considered a best practice for an EC2 instance to use an EBS optimized instance. This provides the best performance for your EBS volumes by minimizing contention between Amazon EBS I/O and other traffic from your instance
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ec2_not_ebs_optimized"
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
ec2_not_ebs_optimized_snippet[violation] {
	ec2_not_ebs_optimized_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

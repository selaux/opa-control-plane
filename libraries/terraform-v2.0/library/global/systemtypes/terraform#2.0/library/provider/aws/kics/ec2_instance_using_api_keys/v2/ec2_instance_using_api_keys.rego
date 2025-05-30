package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ec2_instance_using_api_keys.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

aws_cli_config_files = {"/etc/awscli.conf", "/etc/aws/config", "/etc/aws/credentials", "~/.aws/credentials", "~/.aws/config", "$HOME/.aws/credentials", "$HOME/.aws/config"}

check_aws_api_keys(mdata) {
	count(regex.find_n(`aws_access_key_id\s*=|AWS_ACCESS_KEY_ID\s*=|aws_secret_access_key\s*=|AWS_SECRET_ACCESS_KEY\s*=`, mdata, -1)) > 0
}

check_aws_api_keys_or_config_files(remote) {
	check_aws_api_keys(remote.inline[_0])
} else {
	contains(remote.inline[_], aws_cli_config_files[_])
}

ec2_instance_using_api_keys_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]
	check_aws_api_keys(resource.user_data)
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_instance[%s].user_data is being used to configure AWS API keys", [name]), "keyExpectedValue": sprintf("aws_instance[%s] should be using iam_instance_profile to assign a role with permissions", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s]", [name])}
}

ec2_instance_using_api_keys_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]
	decoded := base64.decode(resource.user_data_base64)
	check_aws_api_keys(decoded)
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_instance[%s].user_data is being used to configure AWS API keys", [name]), "keyExpectedValue": sprintf("aws_instance[%s] should be using iam_instance_profile to assign a role with permissions", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s]", [name])}
}

ec2_instance_using_api_keys_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]
	remote := resource.provisioner["remote-exec"]
	check_aws_api_keys_or_config_files(remote)
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_instance[%s] should be using iam_instance_profile to assign a role with permissions", [name]), "keyExpectedValue": sprintf("aws_instance[%s].provisioner.remote-exec should be used to configure AWS API keys", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s].provisioner", [name])}
}

ec2_instance_using_api_keys_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]
	file := resource.provisioner.file
	contains(file.destination, aws_cli_config_files[_0])
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_instance[%s] should be using iam_instance_profile to assign a role with permissions", [name]), "keyExpectedValue": sprintf("aws_instance[%s].provisioner.file should be used to configure AWS API keys", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s].provisioner", [name])}
}

#######################################################################################################

ec2_instance_using_api_keys_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "user_data")
	check_aws_api_keys(module[keyToCheck])
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("module[%s].user_data is being used to configure AWS API keys", [name]), "keyExpectedValue": sprintf("module[%s] should be using iam_instance_profile to assign a role with permissions", [name]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

ec2_instance_using_api_keys_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "user_data_base64")
	decoded := base64.decode(module[keyToCheck])
	check_aws_api_keys(decoded)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("module[%s].user_data is being used to configure AWS API keys", [name]), "keyExpectedValue": sprintf("module[%s] should be using iam_instance_profile to assign a role with permissions", [name]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EC2 Instance Using API Keys"
# description: >-
#   EC2 instances should use roles to be granted access to other AWS services
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ec2_instance_using_api_keys"
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
ec2_instance_using_api_keys_snippet[violation] {
	ec2_instance_using_api_keys_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}

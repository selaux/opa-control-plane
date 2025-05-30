package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sagemaker_notebook_instance_without_kms.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sagemaker_notebook_instance_without_kms_inner[result] {
	resource := input.document[i].resource.aws_sagemaker_notebook_instance[name]
	not common_lib.valid_key(resource, "kms_key_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_sagemaker_notebook_instance.kms_key_id is undefined or null", "keyExpectedValue": "aws_sagemaker_notebook_instance.kms_key_id should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sagemaker_notebook_instance", "searchKey": sprintf("aws_sagemaker_notebook_instance[{{%s}}]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Sagemaker Notebook Instance Without KMS"
# description: >-
#   AWS SageMaker should encrypt model artifacts at rest using Amazon S3 server-side encryption with an AWS KMS
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sagemaker_notebook_instance_without_kms"
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
#       identifier: aws_sagemaker_notebook_instance
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
sagemaker_notebook_instance_without_kms_snippet[violation] {
	sagemaker_notebook_instance_without_kms_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
